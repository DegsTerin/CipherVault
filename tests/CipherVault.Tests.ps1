BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..' 'CipherVault.ps1'
    . $scriptPath -NoStart
}

Describe 'CipherVault' {
    It 'mantem Base64 personalizado reversivel' {
        $sizes = @(1,2,3,16,31,32,127,256)
        foreach ($size in $sizes) {
            [byte[]]$raw = New-RandomBytes -Length $size
            $encoded = ConvertTo-CustomBase64 -Bytes $raw
            $decoded = ConvertFrom-CustomBase64 -Text $encoded -MaxChars (Get-MaxBase64CharsForBytes -Bytes $size)
            [Convert]::ToBase64String($decoded) | Should -Be ([Convert]::ToBase64String($raw))
        }
    }

    It 'faz round-trip de texto Unicode' {
        $password = 'UnitTest#CipherVault!2026'
        $text = "Bruno áéíóú ãõ ç`r`nLinha 2"
        $encoded = Protect-SecretMessage -PlainText $text -Password $password
        (Unprotect-SecretMessage -EncodedText $encoded -Password $password) | Should -Be $text
    }

    It 'gera ciphertext diferente em execucoes sucessivas' {
        $password = 'UnitTest#CipherVault!2026'
        $text = 'mesma mensagem'
        $a = Protect-SecretMessage -PlainText $text -Password $password
        $b = Protect-SecretMessage -PlainText $text -Password $password
        $a | Should -Not -Be $b
    }

    It 'rejeita senha incorreta' {
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password 'UnitTest#CipherVault!2026'
        { Unprotect-SecretMessage -EncodedText $encoded -Password 'SenhaErrada#2026!' } | Should -Throw '*Falha de autenticacao*'
    }

    It 'rejeita tampering do salt, tag e ciphertext' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        foreach ($component in @(1,3,4)) {
            $tampered = New-TamperedCipherText -EncodedText $encoded -Component $component
            { Unprotect-SecretMessage -EncodedText $tampered -Password $password } | Should -Throw '*Falha de autenticacao*'
        }
    }

    It 'rejeita formatos que nao sejam SC4' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'SC9'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Versao nao suportada*'
    }

    It 'rejeita senha abaixo do limite' {
        { Assert-Password -Password '12345678901' } | Should -Throw '*pelo menos 12 caracteres*'
    }

    It 'rejeita senha acima do limite' {
        { Assert-Password -Password ('A' * 257) } | Should -Throw '*excede o limite de 256*'
    }

    It 'rejeita formato sem cinco campos' {
        { Unprotect-SecretMessage -EncodedText 'SC4.a.b.c' -Password 'UnitTest#CipherVault!2026' } | Should -Throw '*Formato invalido*'
    }

    It 'rejeita Base64 com padding malformado' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[1] = ('!' * 22) + '=!'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*padding malformado*'
    }

    It 'rejeita ciphertext vazio' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[4] = ''
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Ciphertext vazio*'
    }

    It 'escapa controles C0 C1 e Unicode invisivel para exibicao no terminal' {
        $input = ([char]27) + '[2J' + ([char]155) + '31m' + ([char]0x202E) + 'TRUSTED' + ([char]0x200B)
        $safe = ConvertTo-SafeConsoleText -Text $input
        $safe | Should -Not -Match ([char]27)
        $safe | Should -Not -Match ([char]155)
        $safe | Should -Not -Match ([char]0x202E)
        $safe | Should -Not -Match ([char]0x200B)
        $safe | Should -Match '\\u001B'
        $safe | Should -Match '\\u009B'
        $safe | Should -Match '\\u202E'
        $safe | Should -Match '\\u200B'
    }

    It 'rejeita dados estruturais com caractere de controle sem refletir o caractere bruto na excecao' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'teste' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'SC9' + ([char]27) + '[2J'
        try {
            [void](Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password)
            throw 'Teste deveria falhar.'
        }
        catch {
            $_.Exception.Message | Should -Not -Match ([char]27)
        }
    }

    AfterAll {
        Write-Host ''
        Write-Host '  CIPHERVAULT | TESTES FINALIZADOS' -ForegroundColor Cyan
        Write-Host '  A suite de testes foi executada ate o fim.' -ForegroundColor DarkGray
        Write-Host ''
    }
}
