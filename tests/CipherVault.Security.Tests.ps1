BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..' 'CipherVault.ps1'
    . $scriptPath -NoStart
}

Describe 'CipherVault | Offensive security' {
    It 'rejeita entrada aleatoria malformada sem excecao nao tratada' {
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

    It 'rejeita entrada somente com whitespace' {
        { Unprotect-SecretMessage -EncodedText " `t`r`n " -Password 'OffensiveTest#2026!x' } | Should -Throw '*Codigo vazio*'
    }

    It 'rejeita caracteres fora do alfabeto personalizado' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[1] = ($parts[1].Substring(0, $parts[1].Length - 1) + '`')
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*caractere invalido U+0060*'
    }

    It 'mantem limite de plaintext sem derivar chave' {
        $password = 'OffensiveTest#2026!x'
        $oversized = 'A' * ([int]$script:MaxPlaintextBytes + 1)
        { Protect-SecretMessage -PlainText $oversized -Password $password } | Should -Throw '*Mensagem excede o limite*'
    }

    It 'rejeita tag de tamanho incorreto antes do KDF' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[3] = $parts[3].Substring(0, $parts[3].Length - 4)
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Tag com comprimento invalido*'
    }

    It 'rejeita nonce de tamanho incorreto antes do KDF' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[2] = $parts[2] + '!'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Nonce com comprimento invalido*'
    }

    It 'rejeita salt de tamanho incorreto antes do KDF' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[1] = $parts[1] + '!'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Salt com comprimento invalido*'
    }

    It 'rejeita campo extra no ciphertext' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $tampered = $encoded + '.extra'
        { Unprotect-SecretMessage -EncodedText $tampered -Password $password } | Should -Throw '*formato invalido*'
    }

    It 'prioriza caractere invalido sobre erro secundario de padding' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.'
        $parts[1] = ($parts[1].Substring(0, 22) + '`=')
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*caractere invalido U+0060*'
    }

    It 'rejeita mais de cinco componentes estruturais' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        { Unprotect-SecretMessage -EncodedText ($encoded + '.extra') -Password $password } | Should -Throw '*Formato invalido*'
    }

    It 'preserva controles no plaintext, mas os escapa na exibicao' {
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

    It 'nao reflete ESC bruto na mensagem de erro de versao' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'SC9' + ([char]27) + '[2J'
        try {
            [void](Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password)
            throw 'Teste deveria falhar.'
        }
        catch {
            $_.Exception.Message | Should -Not -Match ([char]27)
            $_.Exception.Message | Should -Match 'formato diferente de SC4'
        }
    }
    It 'rejeita whitespace interno no codigo' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[4] = $parts[4].Insert(2, ' ')
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*espaco em branco interno*'
    }

    It 'rejeita Base64 nao canonico' {
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
        { ConvertFrom-CustomBase64 -Text $nonCanonical -MaxChars 4 } | Should -Throw '*representacao nao canonica*'
    }

    It 'rejeita codigo acima do limite antes da descriptografia' {
        $password = 'OffensiveTest#2026!x'
        $oversized = [string]::new('A', [int]$script:MaxEncodedTextChars + 1)
        { Unprotect-SecretMessage -EncodedText $oversized -Password $password } | Should -Throw '*Codigo excede o limite*'
    }

    It 'autentica a AAD e rejeita AAD diferente' {
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

            { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Falha de autenticacao*'
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

    It 'gera pares salt nonce distintos em varias criptografias' {
        $password = 'OffensiveTest#2026!x'
        $pairs = [System.Collections.Generic.HashSet[string]]::new()
        for ($i = 0; $i -lt 8; $i++) {
            $encoded = Protect-SecretMessage -PlainText "nonce-$i" -Password $password
            $parts = $encoded -split '\.', 5
            [void]$pairs.Add("$($parts[1]).$($parts[2])")
        }
        $pairs.Count | Should -Be 8
    }

    It 'escapa separadores Unicode de linha na exibicao' {
        $safe = ConvertTo-SafeConsoleText -Text ("A" + [char]0x2028 + "B" + [char]0x2029 + "C")
        $safe | Should -Be 'A\u2028B\u2029C'
    }


    It 'valida PBKDF2-HMAC-SHA256 contra vetor RFC 7914' {
        [byte[]]$salt = [System.Text.Encoding]::ASCII.GetBytes('salt')
        [byte[]]$derived = Get-DerivedKey -Password 'passwd' -Salt $salt -Iterations 1 -KeySize 64

        $expectedHex = '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'
        $actualHex = -join ($derived | ForEach-Object { $_.ToString('x2') })
        $actualHex | Should -Be $expectedHex
    }

    It 'valida AES-256-GCM contra vetor NIST com plaintext vazio' {
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

    It 'valida AES-256-GCM contra vetor NIST com 16 bytes de plaintext' {
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

    It 'executa round-trip em mensagens Unicode aleatorias' {
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


    It 'rejeita versao SC4 com caixa diferente' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'case' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'sc4'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Versao nao suportada*'
    }

    It 'confirma tamanhos exatos de salt nonce e tag' {
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

    It 'usa salt diferente para derivar chaves diferentes' {
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

    It 'aceita senha Unicode fora do BMP' {
        $password = 'Senha#2026!🔐'
        $text = 'unicode-password'
        $encoded = Protect-SecretMessage -PlainText $text -Password $password
        Unprotect-SecretMessage -EncodedText $encoded -Password $password | Should -Be $text
    }

    It 'rejeita ciphertext truncado que ainda forma Base64 valido' {
        $password = 'OffensiveTest#2026!x'
        $encoded = Protect-SecretMessage -PlainText 'ciphertext truncation test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[4] = $parts[4].Substring(0, $parts[4].Length - 4)
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Falha de autenticacao*'
    }

}
