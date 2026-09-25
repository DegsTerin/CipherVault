#requires -Version 7.4
<#!
.SYNOPSIS
    CipherVault, sistema de criptografia de mensagens em PowerShell.

.DESCRIPTION
    Aplicacao 100% em console. Nao usa Windows Forms, WPF ou modulos externos.

    Criptografia:
      AES-256-GCM para confidencialidade e autenticacao.
      PBKDF2-HMAC-SHA256 com 600.000 iteracoes para derivar a chave da senha.
      Salt aleatorio de 16 bytes e nonce aleatorio de 12 bytes por mensagem.
      Tag GCM de 16 bytes.

    O formato SC4 autentica tambem a versao e os parametros criptograficos por AAD.
    SC4 e o unico formato suportado.

    O alfabeto personalizado altera somente a aparencia do Base64. Nao adiciona
    seguranca criptografica.

.NOTES
    Requer PowerShell 7.4+ e .NET com System.Security.Cryptography.AesGcm.
    Versao do aplicativo: 3.6.0
#>

param(
    [switch]$NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Configuracao
# -----------------------------------------------------------------------------
$script:ProductName = 'CipherVault'
$script:ProductVersion = '3.6.0'
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

# 64 caracteres unicos. Nao contem '.' (separador), '=' (padding) nem controles.
$script:CustomBase64Alphabet = '!@#$%^&*()-_+[]{}|\;:,<>/?~"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

# -----------------------------------------------------------------------------
# Validacao do ambiente e do alfabeto
# -----------------------------------------------------------------------------
function Test-CustomAlphabet {
    $chars = $script:CustomBase64Alphabet.ToCharArray()

    if ($chars.Length -ne 64) {
        throw "Erro interno: alfabeto possui $($chars.Length) caracteres; esperado 64."
    }

    $set = [System.Collections.Generic.HashSet[char]]::new()
    foreach ($char in $chars) {
        if (-not $set.Add($char)) {
            throw "Erro interno: caractere duplicado no alfabeto: '$char'."
        }
    }

    foreach ($forbidden in @('.', '=', "`r", "`n", "`t", ' ')) {
        if ($script:CustomBase64Alphabet.Contains($forbidden)) {
            throw "Erro interno: caractere '$forbidden' nao pode pertencer ao alfabeto."
        }
    }
}

Test-CustomAlphabet

# -----------------------------------------------------------------------------
# Perfis de formato
# -----------------------------------------------------------------------------
function Get-FormatProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('SC4')]
        [string]$Version
    )

    if ($Version -cne 'SC4') {
        throw "Versao nao suportada: $Version."
    }

    # AAD inclui versao + algoritmo + parametros para evitar ambiguidades
    # e para impedir que futuras versoes aceitem downgrade silencioso.
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
# Utilidades criptograficas
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
        # Limpeza e best-effort em ambiente gerenciado.
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
        throw 'Informe uma senha.'
    }

    if ($Password.Length -lt $script:MinPasswordLength) {
        throw "Use uma senha com pelo menos $($script:MinPasswordLength) caracteres."
    }

    if ($Password.Length -gt $script:MaxPasswordLength) {
        throw "A senha excede o limite de $($script:MaxPasswordLength) caracteres."
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
        throw 'Salt vazio.'
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
# Base64 personalizado
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

        # IndexOf(char) e exato para A/a, diferente de Hashtable case-insensitive.
        $index = $script:StandardBase64Alphabet.IndexOf([char]$char)
        if ($index -lt 0) {
            throw "Caractere Base64 inesperado: '$char'."
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
        throw 'Bloco codificado vazio.'
    }

    $clean = $Text.Trim()

    if ($clean.Length -gt $MaxChars) {
        throw "Bloco codificado excede o limite de $MaxChars caracteres."
    }

    # Valida primeiro o alfabeto. Isso garante que um caractere externo
    # nunca seja mascarado por um erro secundario de padding/comprimento.
    foreach ($char in $clean.ToCharArray()) {
        if ($char -eq '=') {
            continue
        }

        if ($script:CustomBase64Alphabet.IndexOf([char]$char) -lt 0) {
            throw ("Codigo contem um caractere invalido U+{0:X4}." -f [int][char]$char)
        }
    }

    $firstPadding = $clean.IndexOf('=')
    if ($firstPadding -ge 0) {
        $padding = $clean.Substring($firstPadding)
        if ($padding.Length -gt 2 -or $padding -notmatch '^={1,2}$') {
            throw 'Base64 invalido: padding malformado.'
        }
    }

    if (($clean.Length % 4) -ne 0) {
        throw 'Base64 invalido: comprimento deve ser multiplo de 4.'
    }

    $builder = [System.Text.StringBuilder]::new($clean.Length)

    foreach ($char in $clean.ToCharArray()) {
        if ($char -eq '=') {
            [void]$builder.Append('=')
            continue
        }

        $index = $script:CustomBase64Alphabet.IndexOf([char]$char)
        # O alfabeto ja foi validado acima. Esta verificacao permanece como
        # defesa adicional caso a implementacao seja alterada no futuro.
        if ($index -lt 0) {
            throw ("Codigo contem um caractere invalido U+{0:X4}." -f [int][char]$char)
        }

        [void]$builder.Append($script:StandardBase64Alphabet[$index])
    }

    try {
        [byte[]]$result = [Convert]::FromBase64String($builder.ToString())
    }
    catch {
        throw 'Um dos blocos do codigo nao e um Base64 valido.'
    }

    # Reencoda para rejeitar representacoes Base64 nao canonicas, incluindo
    # bits de padding nao-zero que alguns decodificadores aceitam.
    $canonical = ConvertTo-CustomBase64 -Bytes $result
    if ($canonical -cne $clean) {
        throw 'Base64 invalido: representacao nao canonica.'
    }

    return $result
}

# -----------------------------------------------------------------------------
# Criptografia / descriptografia
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
        throw 'Digite uma mensagem para criptografar.'
    }

    Assert-Password -Password $Password

    # Preflight conservador: cada caractere .NET ocupa pelo menos um byte em
    # UTF-8. Isso impede a conversao de strings gigantes antes do limite real
    # em bytes ser verificado abaixo. A checagem por bytes continua obrigatoria.
    if ($PlainText.Length -gt $script:MaxPlaintextBytes) {
        throw "Mensagem excede o limite de $($script:MaxPlaintextBytes) bytes."
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
            throw "Mensagem excede o limite de $($script:MaxPlaintextBytes) bytes."
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
        throw 'Codigo vazio.'
    }

    if ($EncodedText.Length -gt $script:MaxEncodedTextChars) {
        throw "Codigo excede o limite de $($script:MaxEncodedTextChars) caracteres."
    }

    $normalized = $EncodedText.Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw 'Codigo vazio.'
    }

    # O formato textual e canonico: whitespace interno nao e aceito.
    # Isso evita multiplas representacoes textuais para os mesmos bytes.
    foreach ($char in $normalized.ToCharArray()) {
        if ([char]::IsWhiteSpace($char)) {
            throw 'Codigo contem espaco em branco interno.'
        }
    }

    $parts = $normalized -split '\.'
    if ($parts.Count -ne 5) {
        throw 'Formato invalido. Esperado: SC4.salt.nonce.tag.ciphertext'
    }

    $version = $parts[0]
    if ($version -cne 'SC4') {
        throw "Versao nao suportada: formato diferente de SC4."
    }

    $profile = Get-FormatProfile -Version 'SC4'

    $expectedSaltChars = Get-MaxBase64CharsForBytes -Bytes $profile.SaltSize
    $expectedNonceChars = Get-MaxBase64CharsForBytes -Bytes $profile.NonceSize
    $expectedTagChars = Get-MaxBase64CharsForBytes -Bytes $profile.TagSize
    $maxCipherChars = Get-MaxBase64CharsForBytes -Bytes $script:MaxCiphertextBytes

    if ($parts[1].Length -ne $expectedSaltChars) { throw 'Salt com comprimento invalido.' }
    if ($parts[2].Length -ne $expectedNonceChars) { throw 'Nonce com comprimento invalido.' }
    if ($parts[3].Length -ne $expectedTagChars) { throw 'Tag com comprimento invalido.' }
    if ($parts[4].Length -gt $maxCipherChars) { throw 'Ciphertext excede o limite permitido.' }
    if ($parts[4].Length -eq 0) { throw 'Ciphertext vazio.' }

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

        if ($salt.Length -ne $profile.SaltSize) { throw 'Salt invalido.' }
        if ($nonce.Length -ne $profile.NonceSize) { throw 'Nonce invalido.' }
        if ($tag.Length -ne $profile.TagSize) { throw 'Tag invalida.' }
        if ($cipherBytes.Length -gt $script:MaxCiphertextBytes) { throw 'Ciphertext excede o limite permitido.' }

        [byte[]]$key = Get-DerivedKey -Password $Password -Salt $salt -Iterations $profile.KdfIterations -KeySize $profile.KeySize
        [byte[]]$plainBytes = [byte[]]::new($cipherBytes.Length)

        $aes = [System.Security.Cryptography.AesGcm]::new($key, $profile.TagSize)

        try {
            $aes.Decrypt($nonce, $cipherBytes, $tag, $plainBytes, $profile.Aad)
        }
        catch [System.Security.Cryptography.CryptographicException] {
            throw 'Falha de autenticacao: senha incorreta ou codigo alterado/corrompido.'
        }

        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        try {
            return $utf8.GetString($plainBytes)
        }
        catch [System.Text.DecoderFallbackException] {
            throw 'Mensagem autenticada, mas o conteudo nao e UTF-8 valido.'
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
# Autotestes criptograficos
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
        throw 'Falha no autoteste: uma alteracao deveria ter sido rejeitada.'
    }
    catch {
        if ($_.Exception.Message -eq 'Falha no autoteste: uma alteracao deveria ter sido rejeitada.') {
            throw
        }
        if ($_.Exception.Message -notmatch 'Falha de autenticacao') {
            throw "Falha no autoteste de rejeicao: $($_.Exception.Message)"
        }
    }
}

function Test-CipherVault {
    $script:SelfTestError = $null
    $testPassword = 'CipherVault-SelfTest#2026!A7'
    $testText = "Teste 123 - acentos: áéíóú âêîôû ãõ ç`r`nLinha 2`nSimbolos: ! @ # $ % & * + ?"

    try {
        # Mapeamento Base64, incluindo tamanhos que cruzam limites de padding.
        foreach ($size in @(1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 127, 256)) {
            [byte[]]$raw = New-RandomBytes -Length $size
            $mapped = ConvertTo-CustomBase64 -Bytes $raw
            [byte[]]$back = ConvertFrom-CustomBase64 -Text $mapped -MaxChars (Get-MaxBase64CharsForBytes -Bytes $size)

            if ($raw.Length -ne $back.Length) {
                throw "Falha no autoteste Base64 no tamanho $size."
            }

            for ($i = 0; $i -lt $raw.Length; $i++) {
                if ($raw[$i] -ne $back[$i]) {
                    throw "Falha no autoteste Base64 no tamanho $size."
                }
            }
        }

        # Round-trip completo.
        $encoded1 = Protect-SecretMessage -PlainText $testText -Password $testPassword
        $decoded1 = Unprotect-SecretMessage -EncodedText $encoded1 -Password $testPassword
        if ($decoded1 -ne $testText) {
            throw 'Round-trip criptografico retornou mensagem diferente.'
        }

        # Mesmo texto + mesma senha deve gerar saidas diferentes.
        $encoded2 = Protect-SecretMessage -PlainText $testText -Password $testPassword
        if ($encoded1 -eq $encoded2) {
            throw 'Salt/nonce nao parecem estar variando entre criptografias.'
        }

        # Senha errada.
        Assert-DecryptionFails -EncodedText $encoded1 -Password 'Senha-Errada#2026!XYZ'

        # Tamper do salt, tag e ciphertext.
        Assert-DecryptionFails -EncodedText (New-TamperedCipherText -EncodedText $encoded1 -Component 1) -Password $testPassword
        Assert-DecryptionFails -EncodedText (New-TamperedCipherText -EncodedText $encoded1 -Component 3) -Password $testPassword
        Assert-DecryptionFails -EncodedText (New-TamperedCipherText -EncodedText $encoded1 -Component 4) -Password $testPassword

        # SC4 e o unico formato suportado; versoes desconhecidas devem ser rejeitadas.
        $parts = $encoded1 -split '\.'
        $parts[0] = 'SC9'
        $unsupportedRejected = $false
        try {
            [void](Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $testPassword)
        }
        catch {
            if ($_.Exception.Message -eq 'Versao nao suportada: formato diferente de SC4.') {
                $unsupportedRejected = $true
            }
            else {
                throw
            }
        }

        if (-not $unsupportedRejected) {
            throw 'Falha no autoteste: uma versao nao suportada deveria ser rejeitada.'
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
    param([string]$Prompt = 'Senha')

    Write-Host "$Prompt (mínimo $($script:MinPasswordLength) caracteres): " -NoNewline -ForegroundColor Gray
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

    # Alem de C0/C1, escapea controles de formato bidirecional e caracteres
    # invisiveis que podem ser usados para spoofing visual em terminais/logs.
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
    Write-Host 'Mensagem:' -ForegroundColor Gray
    Write-Host 'Digite uma linha e pressione Enter.' -ForegroundColor DarkGray
    Write-Host
    return (Read-Host '>')
}

function Read-MultilineFromClipboard {
    Write-Host 'Copie primeiro o texto que deseja criptografar.' -ForegroundColor Gray
    Write-Host 'Depois pressione Enter para ler a area de transferencia.' -ForegroundColor DarkGray
    Write-Host
    [void](Read-Host 'Pressione Enter para continuar')

    $text = Get-ClipboardTextSafe
    if ($null -eq $text) {
        throw 'Nao foi possivel obter texto da area de transferencia.'
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
        throw "Texto do banner excede a largura interna de $Width caracteres."
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
    Write-Host "  Versão $($script:ProductVersion) | PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    Write-Host
}

function Invoke-EncodeFlow {
    param(
        [ValidateSet('Input', 'Clipboard')]
        [string]$Source = 'Input'
    )

    Show-Banner
    Write-Host '  CRIPTOGRAFAR MENSAGEM' -ForegroundColor Cyan
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
            throw 'A mensagem nao pode estar vazia.'
        }

        $result = Protect-SecretMessage -PlainText $plainText -Password $password

        Show-Banner
        Write-Host '  CRIPTOGRAFAR MENSAGEM' -ForegroundColor Cyan
        Write-Rule
        Write-Host
        Write-Host '  RESULTADO:' -ForegroundColor Green
        Write-Host
        Write-Host $result -ForegroundColor White
        Write-Host
        Write-Rule

        if (Copy-ToClipboardSafe -Text $result) {
            Write-Host '  Codigo copiado para a area de transferencia.' -ForegroundColor Green
        }
        else {
            Write-Host '  Copia automatica nao disponivel.' -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host
        Write-Host ("  ERRO: " + (ConvertTo-SafeConsoleText -Text $_.Exception.Message)) -ForegroundColor Red
    }
    finally {
        $password = $null
        $plainText = $null
        $result = $null
    }

    Write-Host
    [void](Read-Host 'Pressione Enter para voltar ao menu')
}

function Invoke-DecodeFlow {
    Show-Banner
    Write-Host '  DESCRIPTOGRAFAR MENSAGEM' -ForegroundColor Cyan
    Write-Rule
    Write-Host

    $password = Read-PasswordHidden

    try {
        Write-Host
        Write-Host 'Cole o codigo completo e pressione Enter.' -ForegroundColor Gray
        Write-Host 'Se deixar vazio, o CipherVault tenta ler a area de transferencia.' -ForegroundColor DarkGray
        Write-Host

        $encodedText = Read-Host 'Codigo'
        if ([string]::IsNullOrWhiteSpace($encodedText)) {
            $encodedText = Get-ClipboardTextSafe
        }

        if ([string]::IsNullOrWhiteSpace($encodedText)) {
            throw 'Nenhum codigo foi informado.'
        }

        $result = Unprotect-SecretMessage -EncodedText $encodedText -Password $password

        Show-Banner
        Write-Host '  DESCRIPTOGRAFAR MENSAGEM' -ForegroundColor Cyan
        Write-Rule
        Write-Host
        Write-Host '  MENSAGEM RECUPERADA:' -ForegroundColor Green
        Write-Host
        Write-Host (ConvertTo-SafeConsoleText -Text $result) -ForegroundColor White
        Write-Host
        Write-Rule
        Write-Host '  Controles de terminal foram escapados para evitar injecao ANSI/VT.' -ForegroundColor DarkGray
    }
    catch {
        Write-Host
        Write-Host ("  ERRO: " + (ConvertTo-SafeConsoleText -Text $_.Exception.Message)) -ForegroundColor Red
    }
    finally {
        $password = $null
        $encodedText = $null
        $result = $null
    }

    Write-Host
    [void](Read-Host 'Pressione Enter para voltar ao menu')
}

function Show-About {
    Show-Banner
    Write-Host '  SOBRE / SEGURANCA' -ForegroundColor Cyan
    Write-Rule
    Write-Host
    Write-Host '  CipherVault e um sistema de criptografia de mensagens em console.'
    Write-Host '  Protecao: AES-256-GCM.'
    Write-Host '  Derivacao: PBKDF2-HMAC-SHA256.'
    Write-Host "  Iteracoes PBKDF2: $($script:KdfIterations)."
    Write-Host '  Salt: 16 bytes | Nonce: 12 bytes | Tag: 16 bytes | Chave: 32 bytes.'
    Write-Host '  Formato: SC4, com algoritmo e parametros vinculados por AAD.'
    Write-Host '  Formatos diferentes de SC4 sao rejeitados.'
    Write-Host "  Limite de mensagem: $($script:MaxPlaintextBytes) bytes."
    Write-Host "  Limite de senha: $($script:MaxPasswordLength) caracteres."
    Write-Host
    Write-Host '  O alfabeto personalizado apenas remapeia o Base64.' -ForegroundColor DarkGray
    Write-Host '  Ele nao aumenta a seguranca criptografica.' -ForegroundColor DarkGray
    Write-Host
    Write-Host '  O resultado e copiado para a area de transferencia quando possivel.' -ForegroundColor DarkGray
    Write-Host '  Mantenha a senha fora do codigo criptografado.' -ForegroundColor Yellow
    Write-Host
    [void](Read-Host 'Pressione Enter para voltar ao menu')
}

function Start-CipherVault {
    try {
        $minimumVersion = [version]'7.4'
        if ([version]$PSVersionTable.PSVersion -lt $minimumVersion) {
            Show-Banner
            Write-Host '  VERSAO DO POWERSHELL NAO SUPORTADA.' -ForegroundColor Red
            Write-Host '  O CipherVault requer PowerShell 7.4 ou superior.' -ForegroundColor Yellow
            Write-Host
            [void](Read-Host 'Pressione Enter para sair')
            return
        }

        if (-not [System.Security.Cryptography.AesGcm]::IsSupported) {
            Show-Banner
            Write-Host '  AES-GCM NAO ESTA DISPONIVEL NESTE AMBIENTE.' -ForegroundColor Red
            Write-Host '  Verifique o PowerShell 7 e o suporte criptografico do .NET.' -ForegroundColor Yellow
            Write-Host
            [void](Read-Host 'Pressione Enter para sair')
            return
        }

        $selfTest = Test-CipherVault
        if (-not $selfTest) {
            Show-Banner
            Write-Host '  ERRO DE INICIALIZACAO' -ForegroundColor Red
            Write-Host '  O autoteste criptografico falhou.' -ForegroundColor Red
            if ($script:SelfTestError) {
                Write-Host "  Detalhe: $($script:SelfTestError)" -ForegroundColor DarkYellow
            }
            Write-Host
            Write-Host '  O programa foi interrompido para evitar uso nao validado.' -ForegroundColor Yellow
            Write-Host
            [void](Read-Host 'Pressione Enter para sair')
            return
        }

        while ($true) {
            Show-Banner
            Write-Host '  [1] Criptografar mensagem' -ForegroundColor White
            Write-Host '  [2] Criptografar texto da area de transferencia' -ForegroundColor White
            Write-Host '  [3] Descriptografar mensagem' -ForegroundColor White
            Write-Host '  [4] Sobre / parametros' -ForegroundColor White
            Write-Host '  [0] Sair' -ForegroundColor White
            Write-Host

            $choice = Read-Host '  Escolha uma opcao'
            Write-Host

            switch ($choice) {
                '1' { Invoke-EncodeFlow -Source Input }
                '2' { Invoke-EncodeFlow -Source Clipboard }
                '3' { Invoke-DecodeFlow }
                '4' { Show-About }
                '0' {
                    Show-Banner
                    Write-Host '  Encerrando CipherVault...' -ForegroundColor DarkGray
                    return
                }
                default {
                    Write-Host '  Opcao invalida.' -ForegroundColor Red
                    [void](Read-Host 'Pressione Enter')
                }
            }
        }
    }
    catch {
        try { [Console]::CursorVisible = $true } catch { }
        Write-Host
        Write-Host ("ERRO FATAL: " + (ConvertTo-SafeConsoleText -Text $_.Exception.Message)) -ForegroundColor Red
        Write-Host
        [void](Read-Host 'Pressione Enter para sair')
    }
}

# UTF-8 evita problemas de caracteres na moldura em hosts compativeis.
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
}
catch { }

if (-not $NoStart) {
    Start-CipherVault
}
