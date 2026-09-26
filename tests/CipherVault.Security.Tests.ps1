BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..' 'CipherVault.ps1'
    . $scriptPath -NoStart
}

Describe 'CipherVault | Offensive security' {
    It 'rejects malformed random input without an unhandled exception' {
        $password = 'OffensiveTest#2026!x'
        $random = [System.Random]::new(1337)

        for ($i = 0; $i -lt 250; $i++) {
            $length = $random.Next(0, 128)
            $chars = [System.Text.StringBuilder]::new($length)
            for ($j = 0; $j -lt $length; $j++) {
                [void]$chars.Append([char]$random.Next(0, 128))
            }

            $succeeded = $false
            try {
                [void](Unprotect-SecretMessage -EncodedText $chars.ToString() -Password $password)
                $succeeded = $true
            }
            catch {
                $_.Exception | Should -Not -BeNullOrEmpty
            }

            $succeeded | Should -BeFalse
        }
    }

    It 'rejects whitespace-only input' {
        { Unprotect-SecretMessage -EncodedText " `t`r`n " -Password 'OffensiveTest#2026!x' } | Should -Throw '*Empty code*'
    }

    It 'rejects characters outside the custom alphabet' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[1] = ($parts[1].Substring(0, $parts[1].Length - 1) + '`')
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*invalid character U+0060*'
    }

    It 'enforces the plaintext limit without deriving the key' {
        $password = 'OffensiveTest#2026!x'
        $oversized = 'A' * ([int]$script:MaxPlaintextBytes + 1)
        { Protect-SecretMessage -PlainText $oversized -Password $password } | Should -Throw '*Message exceeds the limit*'
    }

    It 'rejects an incorrect tag length before the KDF' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[3] = $parts[3].Substring(0, $parts[3].Length - 4)
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Invalid tag length*'
    }

    It 'rejects an incorrect nonce length before the KDF' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[2] = $parts[2] + '!'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Invalid nonce length*'
    }

    It 'rejects an incorrect salt length before the KDF' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[1] = $parts[1] + '!'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Invalid salt length*'
    }

    It 'rejects an extra ciphertext field' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $tampered = $encoded + '.extra'
        { Unprotect-SecretMessage -EncodedText $tampered -Password $password } | Should -Throw '*invalid format*'
    }

    It 'prioritises an invalid character over a secondary padding error' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.'
        $parts[1] = ($parts[1].Substring(0, 22) + '`=')
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*invalid character U+0060*'
    }

    It 'rejects more than five structural components' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        { Unprotect-SecretMessage -EncodedText ($encoded + '.extra') -Password $password } | Should -Throw '*Invalid format*'
    }

    It 'preserves controls in plaintext but escapes them for display' {
        $password = 'OffensiveTest#2026!x'
        $text = "Linha`n`rTab`t" + ([char]27) + 'CTRL' + ([char]0x202E) + 'BIDI'
        $encoded = Protect-SecretMessage -PlainText $text -Password $password
        $decoded = Unprotect-SecretMessage -EncodedText $encoded -Password $password
        $decoded | Should -Be $text
        $safe = ConvertTo-SafeConsoleText -Text $decoded
        $safe | Should -Not -Match ([char]27)
        $safe | Should -Not -Match ([char]0x202E)
        $safe | Should -Match '\\u001B'
        $safe | Should -Match '\\u202E'
    }

    It 'does not reflect raw ESC in the version error message' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'SC9' + ([char]27) + '[2J'
        try {
            [void](Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password)
            throw 'Test should have failed.'
        }
        catch {
            $_.Exception.Message | Should -Not -Match ([char]27)
            $_.Exception.Message | Should -Match 'format other than SC4'
        }
    }
    It 'rejects internal whitespace in the code' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[4] = $parts[4].Insert(2, ' ')
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*internal whitespace*'
    }

    It 'rejects non-canonical Base64' {
        [byte[]]$raw = 0x41
        $canonical = ConvertTo-CustomBase64 -Bytes $raw
        $standard = 'QR=='
        $builder = [System.Text.StringBuilder]::new()
        foreach ($c in $standard.ToCharArray()) {
            if ($c -eq '=') { [void]$builder.Append('='); continue }
            $index = $script:StandardBase64Alphabet.IndexOf([char]$c)
            [void]$builder.Append($script:CustomBase64Alphabet[$index])
        }
        $nonCanonical = $builder.ToString()
        $nonCanonical | Should -Not -Be $canonical
        { ConvertFrom-CustomBase64 -Text $nonCanonical -MaxChars 4 } | Should -Throw '*non-canonical representation*'
    }

    It 'rejects code above the limit before decryption' {
        $password = 'OffensiveTest#2026!x'
        $oversized = [string]::new('A', [int]$script:MaxEncodedTextChars + 1)
        { Unprotect-SecretMessage -EncodedText $oversized -Password $password } | Should -Throw '*Code exceeds the limit*'
    }

    It 'authenticates AAD and rejects different AAD' {
        $password = 'OffensiveTest#2026!x'
        $plaintext = 'AAD test'
        $encoded = Protect-SecretMessage -PlainText $plaintext -Password $password
        $parts = $encoded -split '\.', 5

        [byte[]]$salt = $null
        [byte[]]$nonce = $null
        [byte[]]$wrongTag = $null
        [byte[]]$wrongCipher = $null
        [byte[]]$key = $null
        $aes = $null

        try {
            [byte[]]$salt = ConvertFrom-CustomBase64 -Text $parts[1] -MaxChars 24
            [byte[]]$nonce = ConvertFrom-CustomBase64 -Text $parts[2] -MaxChars 16
            [byte[]]$key = Get-DerivedKey -Password $password -Salt $salt -Iterations 600000 -KeySize 32
            $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
            [byte[]]$plainBytes = $utf8.GetBytes($plaintext)
            [byte[]]$wrongCipher = [byte[]]::new($plainBytes.Length)
            [byte[]]$wrongTag = [byte[]]::new(16)
            $aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
            $wrongAad = [System.Text.Encoding]::UTF8.GetBytes('CipherVault/SC4|AES-256-GCM|PBKDF2-HMAC-SHA256|599999')
            $aes.Encrypt($nonce, $plainBytes, $wrongCipher, $wrongTag, $wrongAad)
            $parts[3] = ConvertTo-CustomBase64 -Bytes $wrongTag
            $parts[4] = ConvertTo-CustomBase64 -Bytes $wrongCipher

            { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Authentication failed*'
        }
        finally {
            if ($null -ne $aes) { $aes.Dispose() }
            Clear-SensitiveBytes -Value $key
            Clear-SensitiveBytes -Value $wrongTag
            Clear-SensitiveBytes -Value $wrongCipher
            Clear-SensitiveBytes -Value $salt
            Clear-SensitiveBytes -Value $nonce
            Clear-SensitiveBytes -Value $plainBytes
        }
    }

    It 'generates distinct salt/nonce pairs across several encryptions' {
        $password = 'OffensiveTest#2026!x'
        $pairs = [System.Collections.Generic.HashSet[string]]::new()
        for ($i = 0; $i -lt 8; $i++) {
            $encoded = Protect-SecretMessage -PlainText "nonce-$i" -Password $password
            $parts = $encoded -split '\.', 5
            [void]$pairs.Add("$($parts[1]).$($parts[2])")
        }
        $pairs.Count | Should -Be 8
    }

    It 'escapes Unicode line separators for display' {
        $safe = ConvertTo-SafeConsoleText -Text ("A" + [char]0x2028 + "B" + [char]0x2029 + "C")
        $safe | Should -Be 'A\u2028B\u2029C'
    }


    It 'validates PBKDF2-HMAC-SHA256 against the RFC 7914 test vector' {
        [byte[]]$salt = [System.Text.Encoding]::ASCII.GetBytes('salt')
        [byte[]]$derived = Get-DerivedKey -Password 'passwd' -Salt $salt -Iterations 1 -KeySize 64

        $expectedHex = '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'
        $actualHex = -join ($derived | ForEach-Object { $_.ToString('x2') })
        $actualHex | Should -Be $expectedHex
    }

    It 'validates AES-256-GCM against the NIST vector with empty plaintext' {
        [byte[]]$key = [byte[]]::new(32)
        [byte[]]$nonce = [byte[]]::new(12)
        [byte[]]$cipher = [byte[]]::new(0)
        [byte[]]$tag = [byte[]]::new(16)
        $aes = $null

        try {
            $aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
            $aes.Encrypt($nonce, $cipher, $cipher, $tag, [byte[]]::new(0))
            $actualTag = -join ($tag | ForEach-Object { $_.ToString('x2') })
            $actualTag | Should -Be '530f8afbc74536b9a963b4f1c4cb738b'
        }
        finally {
            if ($null -ne $aes) { $aes.Dispose() }
            Clear-SensitiveBytes -Value $key
            Clear-SensitiveBytes -Value $tag
        }
    }

    It 'validates AES-256-GCM against the NIST vector with 16 bytes of plaintext' {
        [byte[]]$key = [byte[]]::new(32)
        [byte[]]$nonce = [byte[]]::new(12)
        [byte[]]$plain = [byte[]]::new(16)
        [byte[]]$cipher = [byte[]]::new(16)
        [byte[]]$tag = [byte[]]::new(16)
        $aes = $null

        try {
            $aes = [System.Security.Cryptography.AesGcm]::new($key, 16)
            $aes.Encrypt($nonce, $plain, $cipher, $tag, [byte[]]::new(0))
            $actualCipher = -join ($cipher | ForEach-Object { $_.ToString('x2') })
            $actualTag = -join ($tag | ForEach-Object { $_.ToString('x2') })
            $actualCipher | Should -Be 'cea7403d4d606b6e074ec5d3baf39d18'
            $actualTag | Should -Be 'd0d1c8a799996bf0265b98b5d48ab919'

            [byte[]]$recovered = [byte[]]::new(16)
            $aes.Decrypt($nonce, $cipher, $tag, $recovered, [byte[]]::new(0))
            (-join ($recovered | ForEach-Object { $_.ToString('x2') })) | Should -Be ('00' * 16)
            Clear-SensitiveBytes -Value $recovered
        }
        finally {
            if ($null -ne $aes) { $aes.Dispose() }
            Clear-SensitiveBytes -Value $key
            Clear-SensitiveBytes -Value $plain
            Clear-SensitiveBytes -Value $cipher
            Clear-SensitiveBytes -Value $tag
        }
    }

    It 'performs round-trips on random Unicode messages' {
        $password = 'UnicodeRandom#2026!x'
        $random = [System.Random]::new(73421)

        for ($i = 0; $i -lt 25; $i++) {
            $sb = [System.Text.StringBuilder]::new()
            for ($j = 0; $j -lt 80; $j++) {
                $choice = $random.Next(0, 8)
                switch ($choice) {
                    0 { [void]$sb.Append([char]$random.Next(0x20, 0x7F)) }
                    1 { [void]$sb.Append([char]$random.Next(0x00A0, 0x017F)) }
                    2 { [void]$sb.Append([char]$random.Next(0x0370, 0x03FF)) }
                    3 { [void]$sb.Append([char]$random.Next(0x0400, 0x04FF)) }
                    4 { [void]$sb.Append([char]$random.Next(0x4E00, 0x9FFF)) }
                    5 { [void]$sb.Append([char]$random.Next(0x3040, 0x30FF)) }
                    6 { [void]$sb.Append([System.Char]::ConvertFromUtf32($random.Next(0x1F300, 0x1F64F))) }
                    default { [void]$sb.Append(' ') }
                }
            }

            $text = $sb.ToString()
            $encoded = Protect-SecretMessage -PlainText $text -Password $password
            $decoded = Unprotect-SecretMessage -EncodedText $encoded -Password $password
            $decoded | Should -Be $text
        }
    }


    It 'rejects SC4 with different case' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'case' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'sc4'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Unsupported version*'
    }

    It 'confirms exact salt, nonce and tag sizes' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'tamanhos' -Password $password
        $parts = $encoded -split '\.', 5
        [byte[]]$salt = ConvertFrom-CustomBase64 -Text $parts[1] -MaxChars 24
        [byte[]]$nonce = ConvertFrom-CustomBase64 -Text $parts[2] -MaxChars 16
        [byte[]]$tag = ConvertFrom-CustomBase64 -Text $parts[3] -MaxChars 24
        $salt.Length | Should -Be 16
        $nonce.Length | Should -Be 12
        $tag.Length | Should -Be 16
    }

    It 'uses a different salt to derive different keys' {
        $password = 'OffensiveTest#2026!x'
        $a = Protect-SecretMessage -PlainText 'key-a' -Password $password
        $b = Protect-SecretMessage -PlainText 'key-b' -Password $password
        $pa = $a -split '\.', 5
        $pb = $b -split '\.', 5
        [byte[]]$saltA = ConvertFrom-CustomBase64 -Text $pa[1] -MaxChars 24
        [byte[]]$saltB = ConvertFrom-CustomBase64 -Text $pb[1] -MaxChars 24
        [byte[]]$keyA = Get-DerivedKey -Password $password -Salt $saltA -Iterations 600000 -KeySize 32
        [byte[]]$keyB = Get-DerivedKey -Password $password -Salt $saltB -Iterations 600000 -KeySize 32
        try {
            $saltA | Should -Not -Be $saltB
            (-join ($keyA | ForEach-Object { $_.ToString('x2') })) | Should -Not -Be (-join ($keyB | ForEach-Object { $_.ToString('x2') }))
        }
        finally {
            Clear-SensitiveBytes -Value $saltA
            Clear-SensitiveBytes -Value $saltB
            Clear-SensitiveBytes -Value $keyA
            Clear-SensitiveBytes -Value $keyB
        }
    }

    It 'accepts a Unicode password outside the BMP' {
        $password = 'Password#2026!🔐'
        $text = 'unicode-password'
        $encoded = Protect-SecretMessage -PlainText $text -Password $password
        Unprotect-SecretMessage -EncodedText $encoded -Password $password | Should -Be $text
    }

    It 'rejects truncated ciphertext that remains valid Base64' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'ciphertext truncation test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[4] = $parts[4].Substring(0, $parts[4].Length - 4)
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Authentication failed*'
    }

}
