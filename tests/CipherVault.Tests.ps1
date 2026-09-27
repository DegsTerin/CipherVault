BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..' 'CipherVault.ps1'
    . $scriptPath -NoStart
}

Describe 'CipherVault' {
    It 'keeps custom Base64 reversible' {
        $sizes = @(1,2,3,16,31,32,127,256)
        foreach ($size in $sizes) {
            [byte[]]$raw = New-RandomBytes -Length $size
            $encoded = ConvertTo-CustomBase64 -Bytes $raw
            $decoded = ConvertFrom-CustomBase64 -Text $encoded -MaxChars (Get-MaxBase64CharsForBytes -Bytes $size)
            [Convert]::ToBase64String($decoded) | Should -Be ([Convert]::ToBase64String($raw))
        }
    }

    It 'performs a Unicode text round-trip' {
        $password = 'UnitTest#CipherVault!2026'
        $text = "Bruno áéíóú ãõ ç`r`nLine 2"
        $encoded = Protect-SecretMessage -PlainText $text -Password $password
        (Unprotect-SecretMessage -EncodedText $encoded -Password $password) | Should -Be $text
    }

    It 'generates different ciphertext on successive executions' {
        $password = 'UnitTest#CipherVault!2026'
        $text = 'same message'
        $a = Protect-SecretMessage -PlainText $text -Password $password
        $b = Protect-SecretMessage -PlainText $text -Password $password
        $a | Should -Not -Be $b
    }

    It 'generates secure passwords with equal character-class counts' {
        foreach ($length in @(12, 16, 32, 64, 128, 256)) {
            $password = New-SecurePassword -Length $length

            $password.Length | Should -Be $length
            ([regex]::Matches($password, '[a-z]')).Count | Should -Be ($length / 4)
            ([regex]::Matches($password, '[A-Z]')).Count | Should -Be ($length / 4)
            ([regex]::Matches($password, '[0-9]')).Count | Should -Be ($length / 4)
            ([regex]::Matches($password, '[^a-zA-Z0-9]')).Count | Should -Be ($length / 4)
        }
    }

    It 'rejects password-generator lengths that are not multiples of four' {
        foreach ($length in @(13, 17, 255)) {
            { New-SecurePassword -Length $length } | Should -Throw '*multiple of 4*'
        }
    }

    It 'generates distinct passwords across consecutive requests' {
        $generated = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($iteration in 1..100) {
            $password = New-SecurePassword -Length 64
            $generated.Add($password) | Should -BeTrue
        }
    }

    It 'uses only printable non-whitespace password characters' {
        foreach ($length in @(12, 64, 256)) {
            $password = New-SecurePassword -Length $length
            $password | Should -Not -Match '\s'
            $password | Should -Not -Match '[\x00-\x1F\x7F-\x9F]'
        }
    }
    It 'decrypts an encrypted code read from the clipboard source' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'clipboard test' -Password $password

        Mock -CommandName Read-PasswordHidden -MockWith { $password }
        Mock -CommandName Get-ClipboardTextSafe -MockWith { $encoded }
        Mock -CommandName Read-Host -MockWith { '' }
        Mock -CommandName Show-Banner -MockWith {}
        Mock -CommandName Write-Rule -MockWith {}
        Mock -CommandName Write-Host -MockWith {}

        { Invoke-DecodeFlow -Source Clipboard } | Should -Not -Throw
        Should -Invoke Get-ClipboardTextSafe -Times 1 -Exactly
    }

    It 'rejects an incorrect password' {
        $encoded = Protect-SecretMessage -PlainText 'test' -Password 'UnitTest#CipherVault!2026'
        { Unprotect-SecretMessage -EncodedText $encoded -Password 'WrongPassword#2026!' } | Should -Throw '*Authentication failed*'
    }

    It 'rejects tampering of the salt, tag and ciphertext' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        foreach ($component in @(1,3,4)) {
            $tampered = New-TamperedCipherText -EncodedText $encoded -Component $component
            { Unprotect-SecretMessage -EncodedText $tampered -Password $password } | Should -Throw '*Authentication failed*'
        }
    }

    It 'rejects formats other than SC4' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'SC9'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Unsupported version*'
    }

    It 'rejects a password below the limit' {
        { Assert-Password -Password '12345678901' } | Should -Throw '*at least 12 characters*'
    }

    It 'rejects a password above the limit' {
        { Assert-Password -Password ('A' * 257) } | Should -Throw '*exceeds the 256-character limit*'
    }

    It 'rejects a format without five fields' {
        { Unprotect-SecretMessage -EncodedText 'SC4.a.b.c' -Password 'UnitTest#CipherVault!2026' } | Should -Throw '*Invalid format*'
    }

    It 'rejects Base64 with malformed padding' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[1] = ('!' * 22) + '=!'
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*malformed padding*'
    }

    It 'rejects empty ciphertext' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[4] = ''
        { Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password } | Should -Throw '*Empty ciphertext*'
    }

    It 'escapes C0/C1 controls and invisible Unicode for terminal display' {
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

    It 'rejects structural data containing a control character without reflecting the raw character in the exception' {
        $password = 'UnitTest#CipherVault!2026'
        $encoded = Protect-SecretMessage -PlainText 'test' -Password $password
        $parts = $encoded -split '\.', 5
        $parts[0] = 'SC9' + ([char]27) + '[2J'
        try {
            [void](Unprotect-SecretMessage -EncodedText ($parts -join '.') -Password $password)
            throw 'Test should have failed.'
        }
        catch {
            $_.Exception.Message | Should -Not -Match ([char]27)
        }
    }

    AfterAll {
        Write-Host ''
        Write-Host '  CIPHERVAULT | TESTS COMPLETED' -ForegroundColor Cyan
        Write-Host '  The test suite ran to completion.' -ForegroundColor DarkGray
        Write-Host ''
    }
}
