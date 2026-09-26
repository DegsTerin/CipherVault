#requires -Version 7.4
<#!
.SYNOPSIS
    CipherVault, a message-encryption system for PowerShell.

.DESCRIPTION
    100% console-based. It does not use Windows Forms, WPF or external modules.

    Cryptography:
      AES-256-GCM for confidentiality and authentication.
      PBKDF2-HMAC-SHA256 with 600,000 iterations to derive the password-based key.
      16-byte random salt and 12-byte random nonce per message.
      16-byte GCM tag.

    The SC4 format also authenticates the version and cryptographic parameters through AAD.
    SC4 is the only supported format.

    The custom alphabet only changes the appearance of Base64. It does not add
    cryptographic security.

.NOTES
    Requires PowerShell 7.4+ and .NET with System.Security.Cryptography.AesGcm.
    Application version: 3.6.2
#>

param(
    [switch]$NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
$script:ProductName = 'CipherVault'
$script:ProductVersion = '3.6.2'
$script:CurrentFormatVersion = 'SC4'
$script:KdfIterations = 600000
$script:MinPasswordLength = 12
$script:MaxPasswordLength = 256
$script:MaxPlaintextBytes = [int64](8MB)
$script:MaxCiphertextBytes = [int64](8MB)
$script:MaxEncodedTextChars = [int64](16MB)
$script:SaltSize = 16
$script:NonceSize = 12
$script:TagSize = 16
$script:KeySize = 32

$script:StandardBase64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

# 64 unique characters. Does not contain '.' (separator), '=' (padding) or controls.
$script:CustomBase64Alphabet = '!@#$%^&*()-_+[]{}|\;:,<>/?~"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

# -----------------------------------------------------------------------------
# Environment and alphabet validation
# -----------------------------------------------------------------------------
function Test-CustomAlphabet {
    $chars = $script:CustomBase64Alphabet.ToCharArray()

    if ($chars.Length -ne 64) {
        throw "Internal error: alphabet has $($chars.Length) characters; expected 64."
    }

    $set = [System.Collections.Generic.HashSet[char]]::new()
    foreach ($char in $chars) {
        if (-not $set.Add($char)) {
            throw "Internal error: duplicate character in alphabet: '$char'."
        }
    }

    foreach ($forbidden in @('.', '=', "`r", "`n", "`t", ' ')) {
        if ($script:CustomBase64Alphabet.Contains($forbidden)) {
            throw "Internal error: character '$forbidden' cannot be part of the alphabet."
        }
    }
}

Test-CustomAlphabet

# -----------------------------------------------------------------------------
# Format profiles
# -----------------------------------------------------------------------------
function Get-FormatProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SC4')]
        [string]$Version
    )

    if ($Version -cne 'SC4') {
        throw "Unsupported version: $Version."
    }

    # AAD includes version + algorithm + parameters to prevent ambiguity
    # and to prevent future versions from silently accepting downgrades.
    return [pscustomobject]@{
        Version       = 'SC4'
        KdfIterations = 600000
        SaltSize      = 16
        NonceSize     = 12
        TagSize       = 16
        KeySize       = 32
        Aad           = [System.Text.Encoding]::UTF8.GetBytes('CipherVault/SC4|AES-256-GCM|PBKDF2-HMAC-SHA256|600000')
    }
}

# -----------------------------------------------------------------------------
# Cryptographic utilities
# -----------------------------------------------------------------------------
function New-RandomBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 1048576)]
        [int]$Length
    )

    [byte[]]$bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return $bytes
}

function Clear-SensitiveBytes {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return
    }

    try {
        [byte[]]$bytes = if ($Value -is [byte[]]) { $Value } else { [byte[]]$Value }
        if ($bytes.Length -gt 0) {
            [System.Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    catch {
        # Cleanup is best-effort in a managed environment.
    }
}

function Assert-Password {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Password
    )

    if ([string]::IsNullOrWhiteSpace($Password)) {
        throw 'Enter a password.'
    }

    if ($Password.Length -lt $script:MinPasswordLength) {
        throw "Use a password with at least $($script:MinPasswordLength) characters."
    }

    if ($Password.Length -gt $script:MaxPasswordLength) {
        throw "The password exceeds the $($script:MaxPasswordLength)-character limit."
    }
}

function Get-DerivedKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Password,

        [Parameter(Mandatory)]
        [byte[]]$Salt,

        [Parameter(Mandatory)]
        [int]$Iterations,

        [Parameter(Mandatory)]
        [int]$KeySize
    )

    if ($Salt.Length -lt 1) {
        throw 'Empty salt.'
    }

    [byte[]]$passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)

    try {
        [byte[]]$derivedKey = [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
            $passwordBytes,
            $Salt,
            $Iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            $KeySize
        )

        return $derivedKey
    }
    finally {
        Clear-SensitiveBytes -Value $passwordBytes
    }
}

# -----------------------------------------------------------------------------
# Custom Base64
# -----------------------------------------------------------------------------
function Get-MaxBase64CharsForBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 1073741824)]
        [int64]$Bytes
    )

    return [int64]([math]::Ceiling($Bytes / 3.0) * 4)
}

function ConvertTo-CustomBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )

    $base64 = [Convert]::ToBase64String($Bytes)
    $builder = [System.Text.StringBuilder]::new($base64.Length)

    foreach ($char in $base64.ToCharArray()) {
        if ($char -eq '=') {
            [void]$builder.Append('=')
            continue
        }

        # IndexOf(char) is exact for A/a, unlike a case-insensitive Hashtable.
        $index = $script:StandardBase64Alphabet.IndexOf([char]$char)
        if ($index -lt 0) {
            throw "Unexpected Base64 character: '$char'."
        }

        [void]$builder.Append($script:CustomBase64Alphabet[$index])
    }

    return $builder.ToString()
}

function ConvertFrom-CustomBase64 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [Parameter(Mandatory)]
        [ValidateRange(1, 1073741824)]
        [int64]$MaxChars
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        throw 'Empty encoded block.'
    }

    $clean = $Text.Trim()

    if ($clean.Length -gt $MaxChars) {
        throw "Encoded block exceeds the $MaxChars-character limit."
    }

    # Validate the alphabet first. This ensures that an external character
    # is never masked by a secondary padding/length error.
    foreach ($char in $clean.ToCharArray()) {
        if ($char -eq '=') {
            continue
        }

        if ($script:CustomBase64Alphabet.IndexOf([char]$char) -lt 0) {
            throw ("Code contains an invalid character U+{0:X4}." -f [int][char]$char)
        }
    }

    $firstPadding = $clean.IndexOf('=')
    if ($firstPadding -ge 0) {
        $padding = $clean.Substring($firstPadding)
        if ($padding.Length -gt 2 -or $padding -notmatch '^={1,2}$') {
            throw 'Invalid Base64: malformed padding.'
        }
    }

    if (($clean.Length % 4) -ne 0) {
        throw 'Invalid Base64: length must be a multiple of 4.'
    }

    $builder = [System.Text.StringBuilder]::new($clean.Length)

    foreach ($char in $clean.ToCharArray()) {
        if ($char -eq '=') {
            [void]$builder.Append('=')
            continue
        }

        $index = $script:CustomBase64Alphabet.IndexOf([char]$char)
        # The alphabet has already been validated above. This check remains as
        # additional defence if the implementation is changed in the future.
        if ($index -lt 0) {
            throw ("Code contains an invalid character U+{0:X4}." -f [int][char]$char)
        }

        [void]$builder.Append($script:StandardBase64Alphabet[$index])
    }

    try {
        [byte[]]$result = [Convert]::FromBase64String($builder.ToString())
    }
    catch {
        throw 'One of the code blocks is not valid Base64.'
    }

    # Re-encode to reject non-canonical Base64 representations, including
    # non-zero padding bits that some decoders accept.
    $canonical = ConvertTo-CustomBase64 -Bytes $result
    if ($canonical -cne $clean) {
        throw 'Invalid Base64: non-canonical representation.'
    }

    return $result
}

# -----------------------------------------------------------------------------
# Encryption / decryption
# -----------------------------------------------------------------------------
function Protect-SecretMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$PlainText,

        [Parameter(Mandatory)]
        [string]$Password
    )

    if ([string]::IsNullOrEmpty($PlainText)) {
        throw 'Enter a message to encrypt.'
    }

    Assert-Password -Password $Password

    # Conservative preflight: each .NET character occupies at least one byte in
    # UTF-8. This prevents conversion of very large strings before the actual
    # byte limit is checked below. The byte-level check remains mandatory.
    if ($PlainText.Length -gt $script:MaxPlaintextBytes) {
        throw "Message exceeds the limit of $($script:MaxPlaintextBytes) bytes."
    }

    $profile = Get-FormatProfile -Version $script:CurrentFormatVersion

    [byte[]]$salt = $null
    [byte[]]$nonce = $null
    [byte[]]$key = $null
    [byte[]]$plainBytes = $null
    [byte[]]$cipherBytes = $null
    [byte[]]$tag = $null
    $aes = $null

    try {
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        [byte[]]$plainBytes = $utf8.GetBytes($PlainText)

        if ($plainBytes.Length -gt $script:MaxPlaintextBytes) {
            throw "Message exceeds the limit of $($script:MaxPlaintextBytes) bytes."
        }

        [byte[]]$salt = New-RandomBytes -Length $profile.SaltSize
        [byte[]]$nonce = New-RandomBytes -Length $profile.NonceSize
        [byte[]]$key = Get-DerivedKey -Password $Password -Salt $salt -Iterations $profile.KdfIterations -KeySize $profile.KeySize
        [byte[]]$cipherBytes = [byte[]]::new($plainBytes.Length)
        [byte[]]$tag = [byte[]]::new($profile.TagSize)

        $aes = [System.Security.Cryptography.AesGcm]::new($key, $profile.TagSize)
        $aes.Encrypt($nonce, $plainBytes, $cipherBytes, $tag, $profile.Aad)

        $saltText = ConvertTo-CustomBase64 -Bytes $salt
        $nonceText = ConvertTo-CustomBase64 -Bytes $nonce
        $tagText = ConvertTo-CustomBase64 -Bytes $tag
        $cipherText = ConvertTo-CustomBase64 -Bytes $cipherBytes

        return "{0}.{1}.{2}.{3}.{4}" -f $profile.Version, $saltText, $nonceText, $tagText, $cipherText
    }
    finally {
        if ($null -ne $aes) { $aes.Dispose() }
        Clear-SensitiveBytes -Value $key
        Clear-SensitiveBytes -Value $plainBytes
        Clear-SensitiveBytes -Value $cipherBytes
        Clear-SensitiveBytes -Value $tag
        Clear-SensitiveBytes -Value $salt
        Clear-SensitiveBytes -Value $nonce
    }
}

function Unprotect-SecretMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EncodedText,

        [Parameter(Mandatory)]
        [string]$Password
    )

    Assert-Password -Password $Password

    if ([string]::IsNullOrWhiteSpace($EncodedText)) {
        throw 'Empty code.'
    }

    if ($EncodedText.Length -gt $script:MaxEncodedTextChars) {
        throw "Code exceeds the limit of $($script:MaxEncodedTextChars) characters."
    }

    $normalized = $EncodedText.Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw 'Empty code.'
    }

    # The textual format is canonical: internal whitespace is not accepted.
    # This prevents multiple textual representations of the same bytes.
    foreach ($char in $normalized.ToCharArray()) {
        if ([char]::IsWhiteSpace($char)) {
            throw 'Code contains internal whitespace.'
        }
    }

    $parts = $normalized -split '\.'
    if ($parts.Count -ne 5) {
        throw 'Invalid format. Expected: SC4.salt.nonce.tag.ciphertext'
    }

    $version = $parts[0]
    if ($version -cne 'SC4') {
        throw "Unsupported version: format other than SC4."
    }

    $profile = Get-FormatProfile -Version 'SC4'

    $expectedSaltChars = Get-MaxBase64CharsForBytes -Bytes $profile.SaltSize
    $expectedNonceChars = Get-MaxBase64CharsForBytes -Bytes $profile.NonceSize
    $expectedTagChars = Get-MaxBase64CharsForBytes -Bytes $profile.TagSize
    $maxCipherChars = Get-MaxBase64CharsForBytes -Bytes $script:MaxCiphertextBytes

    if ($parts[1].Length -ne $expectedSaltChars) { throw 'Invalid salt length.' }
    if ($parts[2].Length -ne $expectedNonceChars) { throw 'Invalid nonce length.' }
    if ($parts[3].Length -ne $expectedTagChars) { throw 'Invalid tag length.' }
    if ($parts[4].Length -gt $maxCipherChars) { throw 'Ciphertext exceeds the permitted limit.' }
    if ($parts[4].Length -eq 0) { throw 'Empty ciphertext.' }

    [byte[]]$salt = $null
    [byte[]]$nonce = $null
    [byte[]]$tag = $null
    [byte[]]$cipherBytes = $null
    [byte[]]$key = $null
    [byte[]]$plainBytes = $null
    $aes = $null

    try {
        [byte[]]$salt = ConvertFrom-CustomBase64 -Text $parts[1] -MaxChars $expectedSaltChars
        [byte[]]$nonce = ConvertFrom-CustomBase64 -Text $parts[2] -MaxChars $expectedNonceChars
        [byte[]]$tag = ConvertFrom-CustomBase64 -Text $parts[3] -MaxChars $expectedTagChars
        [byte[]]$cipherBytes = ConvertFrom-CustomBase64 -Text $parts[4] -MaxChars $maxCipherChars

        if ($salt.Length -ne $profile.SaltSize) { throw 'Invalid salt.' }
        if ($nonce.Length -ne $profile.NonceSize) { throw 'Invalid nonce.' }
        if ($tag.Length -ne $profile.TagSize) { throw 'Invalid tag.' }
        if ($cipherBytes.Length -gt $script:MaxCiphertextBytes) { throw 'Ciphertext exceeds the permitted limit.' }

        [byte[]]$key = Get-DerivedKey -Password $Password -Salt $salt -Iterations $profile.KdfIterations -KeySize $profile.KeySize
        [byte[]]$plainBytes = [byte[]]::new($cipherBytes.Length)

        $aes = [System.Security.Cryptography.AesGcm]::new($key, $profile.TagSize)

        try {
            $aes.Decrypt($nonce, $cipherBytes, $tag, $plainBytes, $profile.Aad)
        }
        catch [System.Security.Cryptography.CryptographicException] {
            throw 'Authentication failed: incorrect password or altered/corrupted code.'
        }

        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        try {
            return $utf8.GetString($plainBytes)
        }
        catch [System.Text.DecoderFallbackException] {
            throw 'Message authenticated, but the content is not valid UTF-8.'
        }
    }
    finally {
        if ($null -ne $aes) { $aes.Dispose() }
        Clear-SensitiveBytes -Value $key
        Clear-SensitiveBytes -Value $plainBytes
        Clear-SensitiveBytes -Value $cipherBytes
        Clear-SensitiveBytes -Value $salt
        Clear-SensitiveBytes -Value $nonce
        Clear-SensitiveBytes -Value $tag
    }
}

# -----------------------------------------------------------------------------
# Cryptographic self-tests
# -----------------------------------------------------------------------------
function New-TamperedCipherText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EncodedText,

        [Parameter(Mandatory)]
        [ValidateSet(1, 2, 3, 4)]
        [int]$Component
    )

    $parts = $EncodedText -split '\.'
    $value = $parts[$Component]
    $replacement = $script:CustomBase64Alphabet[0]
    if ($value[0] -eq $replacement) {
        $replacement = $script:CustomBase64Alphabet[1]
    }

    $parts[$Component] = $replacement + $value.Substring(1)
    return ($parts -join '.')
}

function Assert-DecryptionFails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$EncodedText,

        [Parameter(Mandatory)]
        [string]$Password
    )

    try {
        [void](Unprotect-SecretMessage -EncodedText $EncodedText -Password $Password)
        throw 'Self-test failure: a modification should have been rejected.'
    }
    catch {
        if ($_.Exception.Message -eq 'Self-test failure: a modification should have been rejected.') {
            throw
        }
        if ($_.Exception.Message -notmatch 'Authentication failed') {
            throw "Rejection self-test failure: $($_.Exception.Message)"
        }
    }
}

function Test-CipherVault {
    $script:SelfTestError = $null
    $testPassword = 'CipherVault-SelfTest#2026!A7'
    $testText = "Test 123 - accents: áéíóú âêîôû ãõ ç`r`nLine 2`nSymbols: ! @ # $ % & * + ?"

    try {
        # Base64 mapping, including sizes that cross padding boundaries.
        foreach ($size in @(1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 127, 256)) {
            [byte[]]$raw = New-RandomBytes -Length $size
            $mapped = ConvertTo-CustomBase64 -Bytes $raw
            [byte[]]$back = ConvertFrom-CustomBase64 -Text $mapped -MaxChars (Get-MaxBase64CharsForBytes -Bytes $size)

            if ($raw.Length -ne $back.Length) {
                throw "Base64 self-test failure at size $size."
            }

            for ($i = 0; $i -lt $raw.Length; $i++) {
                if ($raw[$i] -ne $back[$i]) {
                    throw "Base64 self-test failure at size $size."
                }
            }
        }

        # Full round-trip.
        $encoded1 = Protect-SecretMessage -PlainText $testText -Password $testPassword
        $decoded1 = Unprotect-SecretMessage -EncodedText $encoded1 -Password $testPassword
        if ($decoded1 -ne $testText) {
            throw 'Cryptographic round-trip returned a different message.'
        }

        # The same text + same password should generate different outputs.
        $encoded2 = Protect-SecretMessage -PlainText $testText -Password $testPassword
        if ($encoded1 -eq $encoded2) {
            throw 'Salt/nonce do not appear to vary between encryptions.'
        }

        # Incorrect password.
        Assert-DecryptionFails -EncodedText $encoded1 -Password 'Wrong-Password#2026!XYZ'

        # Tamper with salt, tag and ciphertext.
        Assert-DecryptionFails -EncodedText (New-TamperedCipherText -EncodedText $encoded1 -Component 1) -Password $testPassword
        Assert-DecryptionFails -EncodedText (New-TamperedCipherText -EncodedText $encoded1 -Component 3) -Password $testPassword
        Assert-DecryptionFails -EncodedText (New-TamperedCipherText -EncodedText $encoded1 -Component 4) -Password $testPassword

        # SC4 is the only supported format; unknown versions must be rejected.
        $parts = $encoded1 -split '\.'
        $parts[0] = 'SC9'
        $unsupportedRejected = $false
        try {
            [void](Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $testPassword)
        }
        catch {
            if ($_.Exception.Message -eq 'Unsupported version: format other than SC4.') {
                $unsupportedRejected = $true
            }
            else {
                throw
            }
        }

        if (-not $unsupportedRejected) {
            throw 'Self-test failure: an unsupported version should have been rejected.'
        }

        return $true
    }
    catch {
        $script:SelfTestError = $_.Exception.Message
        return $false
    }
}

# -----------------------------------------------------------------------------
# Console
# -----------------------------------------------------------------------------
function Read-PasswordHidden {
    param([string]$Prompt = 'Password')

    Write-Host "$Prompt (minimum $($script:MinPasswordLength) characters): " -NoNewline -ForegroundColor Gray
    [char[]]$buffer = [char[]]::new($script:MaxPasswordLength)
    [int]$count = 0

    try {
        while ($true) {
            $key = [Console]::ReadKey($true)

            if ($key.Key -eq [ConsoleKey]::Enter) { break }

            if ($key.Key -eq [ConsoleKey]::Backspace) {
                if ($count -gt 0) {
                    $count--
                    $buffer[$count] = [char]0
                    Write-Host "`b `b" -NoNewline
                }
                continue
            }

            if ([char]::IsControl($key.KeyChar)) { continue }

            if ($count -ge $script:MaxPasswordLength) {
                [Console]::Beep(800, 60)
                continue
            }

            $buffer[$count] = $key.KeyChar
            $count++
            Write-Host '*' -NoNewline
        }

        Write-Host
        return [string]::new($buffer, 0, $count)
    }
    finally {
        [System.Array]::Clear($buffer, 0, $buffer.Length)
    }
}

function Copy-ToClipboardSafe {
    param([Parameter(Mandatory)][string]$Text)

    try {
        if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
            Set-Clipboard -Value $Text -ErrorAction Stop
            return $true
        }
    }
    catch { }

    return $false
}

function Get-ClipboardTextSafe {
    try {
        if (Get-Command Get-Clipboard -ErrorAction SilentlyContinue) {
            $text = Get-Clipboard -Raw -ErrorAction Stop
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                return $text
            }
        }
    }
    catch { }

    return $null
}

function ConvertTo-SafeConsoleText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )

    # In addition to C0/C1, escape bidirectional formatting controls and
    # invisible characters that can be used for visual spoofing in terminals/logs.
    $unsafeUnicode = @(
        0x061C,       # Arabic Letter Mark
        0x180E,       # Mongolian Vowel Separator
        0x200B,       # Zero Width Space
        0x200C,       # Zero Width Non-Joiner
        0x200D,       # Zero Width Joiner
        0x200E,       # Left-to-Right Mark
        0x200F,       # Right-to-Left Mark
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
        0x2060,       # Word Joiner
        0x2066, 0x2067, 0x2068, 0x2069,
        0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F,
        0x2028, 0x2029,       # Line Separator / Paragraph Separator
        0xFEFF        # Zero Width No-Break Space / BOM
    )

    $builder = [System.Text.StringBuilder]::new($Text.Length)

    foreach ($char in $Text.ToCharArray()) {
        $code = [int][char]$char

        if ($code -eq 10) {
            [void]$builder.Append("`n")
        }
        elseif ($code -eq 9) {
            [void]$builder.Append('    ')
        }
        elseif ($code -lt 32 -or ($code -ge 127 -and $code -le 159) -or ($unsafeUnicode -contains $code)) {
            [void]$builder.Append(('\u{0:X4}' -f $code))
        }
        else {
            [void]$builder.Append($char)
        }
    }

    return $builder.ToString()
}

function Read-SingleLineMessage {
    Write-Host 'Message:' -ForegroundColor Gray
    Write-Host 'Type one line and press Enter.' -ForegroundColor DarkGray
    Write-Host
    return (Read-Host '>')
}

function Read-MultilineFromClipboard {
    Write-Host 'First copy the text you want to encrypt.' -ForegroundColor Gray
    Write-Host 'Then press Enter to read the clipboard.' -ForegroundColor DarkGray
    Write-Host
    [void](Read-Host 'Press Enter to continue')

    $text = Get-ClipboardTextSafe
    if ($null -eq $text) {
        throw 'Unable to retrieve text from the clipboard.'
    }

    return $text
}

function Format-BannerLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [ValidateRange(20, 120)]
        [int]$Width = 62
    )

    if ($Text.Length -gt $Width) {
        throw "Banner text exceeds the internal width of $Width characters."
    }

    $padding = $Width - $Text.Length
    $left = [math]::Floor($padding / 2)
    $right = $padding - $left

    return ('║' + (' ' * $left) + $Text + (' ' * $right) + '║')
}

function Write-Rule {
    [CmdletBinding()]
    param(
        [ValidateRange(20, 120)]
        [int]$Width = 62
    )

    Write-Host ("  " + ('─' * $Width)) -ForegroundColor DarkGray
}

function Show-Banner {
    Clear-Host

    $width = 62
    $top = '╔' + ('═' * $width) + '╗'
    $bottom = '╚' + ('═' * $width) + '╝'

    Write-Host
    Write-Host ("  $top") -ForegroundColor DarkGray
    Write-Host ("  $(Format-BannerLine -Text 'CIPHERVAULT' -Width $width)") -ForegroundColor DarkGray
    Write-Host ("  $(Format-BannerLine -Text 'AES-256-GCM + PBKDF2-HMAC-SHA256' -Width $width)") -ForegroundColor DarkGray
    Write-Host ("  $bottom") -ForegroundColor DarkGray
    Write-Host "  Version $($script:ProductVersion) | PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    Write-Host
}

function Invoke-EncodeFlow {
    param(
        [ValidateSet('Input', 'Clipboard')]
        [string]$Source = 'Input'
    )

    Show-Banner
    Write-Host '  ENCRYPT MESSAGE' -ForegroundColor Cyan
    Write-Rule
    Write-Host

    $password = Read-PasswordHidden

    try {
        if ($Source -eq 'Clipboard') {
            $plainText = Read-MultilineFromClipboard
        }
        else {
            $plainText = Read-SingleLineMessage
        }

        if ([string]::IsNullOrEmpty($plainText)) {
            throw 'The message cannot be empty.'
        }

        $result = Protect-SecretMessage -PlainText $plainText -Password $password

        Show-Banner
        Write-Host '  ENCRYPT MESSAGE' -ForegroundColor Cyan
        Write-Rule
        Write-Host
        Write-Host '  RESULT:' -ForegroundColor Green
        Write-Host
        Write-Host $result -ForegroundColor White
        Write-Host
        Write-Rule

        if (Copy-ToClipboardSafe -Text $result) {
            Write-Host '  Code copied to the clipboard.' -ForegroundColor Green
        }
        else {
            Write-Host '  Automatic copy is not available.' -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host
        Write-Host ("  ERROR: " + (ConvertTo-SafeConsoleText -Text $_.Exception.Message)) -ForegroundColor Red
    }
    finally {
        $password = $null
        $plainText = $null
        $result = $null
    }

    Write-Host
    [void](Read-Host 'Press Enter to return to the menu')
}

function Invoke-DecodeFlow {
    Show-Banner
    Write-Host '  DECRYPT MESSAGE' -ForegroundColor Cyan
    Write-Rule
    Write-Host

    $password = Read-PasswordHidden

    try {
        Write-Host
        Write-Host 'Paste the complete code and press Enter.' -ForegroundColor Gray
        Write-Host 'If left empty, CipherVault tries to read the clipboard.' -ForegroundColor DarkGray
        Write-Host

        $encodedText = Read-Host 'Code'
        if ([string]::IsNullOrWhiteSpace($encodedText)) {
            $encodedText = Get-ClipboardTextSafe
        }

        if ([string]::IsNullOrWhiteSpace($encodedText)) {
            throw 'No code was provided.'
        }

        $result = Unprotect-SecretMessage -EncodedText $encodedText -Password $password

        Show-Banner
        Write-Host '  DECRYPT MESSAGE' -ForegroundColor Cyan
        Write-Rule
        Write-Host
        Write-Host '  RECOVERED MESSAGE:' -ForegroundColor Green
        Write-Host
        Write-Host (ConvertTo-SafeConsoleText -Text $result) -ForegroundColor White
        Write-Host
        Write-Rule
        Write-Host '  Terminal controls were escaped to prevent ANSI/VT injection.' -ForegroundColor DarkGray
    }
    catch {
        Write-Host
        Write-Host ("  ERROR: " + (ConvertTo-SafeConsoleText -Text $_.Exception.Message)) -ForegroundColor Red
    }
    finally {
        $password = $null
        $encodedText = $null
        $result = $null
    }

    Write-Host
    [void](Read-Host 'Press Enter to return to the menu')
}

function Show-About {
    Show-Banner
    Write-Host '  ABOUT / SECURITY' -ForegroundColor Cyan
    Write-Rule
    Write-Host
    Write-Host '  CipherVault is a console-based message-encryption system.'
    Write-Host '  Protection: AES-256-GCM.'
    Write-Host '  Key derivation: PBKDF2-HMAC-SHA256.'
    Write-Host "  PBKDF2 iterations: $($script:KdfIterations)."
    Write-Host '  Salt: 16 bytes | Nonce: 12 bytes | Tag: 16 bytes | Key: 32 bytes.'
    Write-Host '  Format: SC4, with the algorithm and parameters bound by AAD.'
    Write-Host '  Formats other than SC4 are rejected.'
    Write-Host "  Message limit: $($script:MaxPlaintextBytes) bytes."
    Write-Host "  Password limit: $($script:MaxPasswordLength) characters."
    Write-Host
    Write-Host '  The custom alphabet only remaps Base64.' -ForegroundColor DarkGray
    Write-Host '  It does not increase cryptographic security.' -ForegroundColor DarkGray
    Write-Host
    Write-Host '  The result is copied to the clipboard when possible.' -ForegroundColor DarkGray
    Write-Host '  Keep the password separate from the encrypted code.' -ForegroundColor Yellow
    Write-Host
    [void](Read-Host 'Press Enter to return to the menu')
}

function Start-CipherVault {
    try {
        $minimumVersion = [version]'7.4'
        if ([version]$PSVersionTable.PSVersion -lt $minimumVersion) {
            Show-Banner
            Write-Host '  UNSUPPORTED POWERSHELL VERSION.' -ForegroundColor Red
            Write-Host '  CipherVault requires PowerShell 7.4 or later.' -ForegroundColor Yellow
            Write-Host
            [void](Read-Host 'Press Enter to exit')
            return
        }

        if (-not [System.Security.Cryptography.AesGcm]::IsSupported) {
            Show-Banner
            Write-Host '  AES-GCM IS NOT AVAILABLE IN THIS ENVIRONMENT.' -ForegroundColor Red
            Write-Host '  Check PowerShell 7 and .NET cryptographic support.' -ForegroundColor Yellow
            Write-Host
            [void](Read-Host 'Press Enter to exit')
            return
        }

        $selfTest = Test-CipherVault
        if (-not $selfTest) {
            Show-Banner
            Write-Host '  INITIALISATION ERROR' -ForegroundColor Red
            Write-Host '  The cryptographic self-test failed.' -ForegroundColor Red
            if ($script:SelfTestError) {
                Write-Host "  Detail: $($script:SelfTestError)" -ForegroundColor DarkYellow
            }
            Write-Host
            Write-Host '  The program was stopped to avoid using an unvalidated mechanism.' -ForegroundColor Yellow
            Write-Host
            [void](Read-Host 'Press Enter to exit')
            return
        }

        while ($true) {
            Show-Banner
            Write-Host '  [1] Encrypt message' -ForegroundColor White
            Write-Host '  [2] Encrypt clipboard text' -ForegroundColor White
            Write-Host '  [3] Decrypt message' -ForegroundColor White
            Write-Host '  [4] About / parameters' -ForegroundColor White
            Write-Host '  [0] Exit' -ForegroundColor White
            Write-Host

            $choice = Read-Host '  Choose an option'
            Write-Host

            switch ($choice) {
                '1' { Invoke-EncodeFlow -Source Input }
                '2' { Invoke-EncodeFlow -Source Clipboard }
                '3' { Invoke-DecodeFlow }
                '4' { Show-About }
                '0' {
                    Show-Banner
                    Write-Host '  Exiting CipherVault...' -ForegroundColor DarkGray
                    return
                }
                default {
                    Write-Host '  Invalid option.' -ForegroundColor Red
                    [void](Read-Host 'Press Enter')
                }
            }
        }
    }
    catch {
        try { [Console]::CursorVisible = $true } catch { }
        Write-Host
        Write-Host ("FATAL ERROR: " + (ConvertTo-SafeConsoleText -Text $_.Exception.Message)) -ForegroundColor Red
        Write-Host
        [void](Read-Host 'Press Enter to exit')
    }
}

# UTF-8 avoids character issues in the border on compatible hosts.
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
}
catch { }

if (-not $NoStart) {
    Start-CipherVault
}
