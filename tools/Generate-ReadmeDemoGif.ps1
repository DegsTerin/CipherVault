#Requires -Version 7.4

<#
.SYNOPSIS
    Generates the animated terminal demonstration used by the README.

.DESCRIPTION
    Creates four high-resolution terminal-style PNG frames with System.Drawing
    and combines them into an animated GIF with ImageMagick.

    This script is a repository-content generator only. It is not part of the
    CipherVault runtime or cryptographic implementation.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$outputDirectory = Join-Path $PSScriptRoot '..' 'assets'
$frameDirectory = Join-Path $env:RUNNER_TEMP 'ciphervault-demo-frames'
$outputPath = Join-Path $outputDirectory 'ciphervault-demo.gif'

$width = 1024
$height = 576

New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
if (Test-Path $frameDirectory) {
    Remove-Item -Path $frameDirectory -Recurse -Force
}
New-Item -ItemType Directory -Path $frameDirectory -Force | Out-Null

Add-Type -AssemblyName System.Drawing

$fontFamily = [System.Drawing.FontFamily]::new('Consolas')
$font = [System.Drawing.Font]::new($fontFamily, 20.0, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$smallFont = [System.Drawing.Font]::new($fontFamily, 15.0, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$accentBrush = [System.Drawing.Brushes]::LimeGreen
$textBrush = [System.Drawing.Brushes]::White
$mutedBrush = [System.Drawing.Brushes]::LightGray
$borderPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(90, 100, 110), 1.0)

$frames = @(
    @(
        'CIPHERVAULT 3.6.2',
        'AES-256-GCM + PBKDF2-HMAC-SHA256',
        'Version 3.6.2 | PowerShell 7.6.6',
        '============================================================',
        '[1] Encrypt message',
        '[2] Encrypt clipboard text',
        '[3] Decrypt message',
        '[4] Decrypt clipboard text',
        '[5] Generate secure password',
        '[6] About / parameters',
        '[0] Exit',
        '',
        'Choose an option: 2'
    ),
    @(
        'CIPHERVAULT 3.6.2',
        'ENCRYPT CLIPBOARD TEXT',
        '============================================================',
        '',
        'Password (minimum 12, maximum 256 characters): ********',
        '',
        'First copy the text you want to encrypt.',
        'Then press Enter to read the clipboard.',
        '',
        'Press Enter to continue:',
        '',
        'RESULT: SC4.<encrypted code>',
        'Code copied to the clipboard.'
    ),
    @(
        'CIPHERVAULT 3.6.2',
        'DECRYPT CLIPBOARD TEXT',
        '============================================================',
        '',
        'Password (minimum 12, maximum 256 characters): ********',
        '',
        'First copy the encrypted code you want to decrypt.',
        'Then press Enter to read the clipboard.',
        '',
        'RECOVERED MESSAGE:',
        '',
        'Hello from CipherVault.',
        'This message was decrypted locally.'
    ),
    @(
        'CIPHERVAULT 3.6.2',
        'GENERATE SECURE PASSWORD',
        '============================================================',
        '',
        'Choose a length from 12 to 256 characters.',
        'The length must be a multiple of 4.',
        '',
        'Password length: 32',
        '',
        'GENERATED PASSWORD (32 characters):',
        '',
        'aQ7!mP2#xL9@T4$kV8&nR5%wC6^zH1*',
        '',
        'Password copied to the clipboard.'
    )
)

$generatedFrames = @()

try {
    for ($index = 0; $index -lt $frames.Count; $index++) {
        $bitmap = [System.Drawing.Bitmap]::new($width, $height, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)

        try {
            $graphics.Clear([System.Drawing.Color]::FromArgb(8, 10, 12))
            $graphics.DrawRectangle($borderPen, 12, 12, $width - 25, $height - 25)

            $y = 34
            foreach ($line in $frames[$index]) {
                if ($line -like 'CIPHERVAULT*' -or $line -like '*PASSWORD*' -or $line -like '*ENCRYPT*' -or $line -like '*DECRYPT*') {
                    $brush = $accentBrush
                }
                elseif ($line -eq '============================================================') {
                    $brush = $mutedBrush
                }
                else {
                    $brush = $textBrush
                }

                $graphics.DrawString($line, $font, $brush, 38, $y)
                $y += 29
            }

            $graphics.DrawString(
                'Console-only | PowerShell 7.4+ | local encryption',
                $smallFont,
                $mutedBrush,
                38,
                $height - 36
            )
        }
        finally {
            $graphics.Dispose()
        }

        $framePath = Join-Path $frameDirectory ('frame-{0:D2}.png' -f $index)
        $bitmap.Save($framePath, [System.Drawing.Imaging.ImageFormat]::Png)
        $bitmap.Dispose()
        $generatedFrames += $framePath
    }

    $magick = Get-Command magick -ErrorAction Stop
    $magickArguments = @(
        '-quiet'
        '-background'
        'black'
        '-delay'
        '260'
        '-loop'
        '0'
    ) + $generatedFrames + @($outputPath)

    & $magick.Source @magickArguments

    if ($LASTEXITCODE -ne 0) {
        throw "ImageMagick failed with exit code $LASTEXITCODE."
    }

    if (-not (Test-Path $outputPath)) {
        throw 'The demo GIF was not generated.'
    }

    Write-Host "Generated: $outputPath"
}
finally {
    $font.Dispose()
    $smallFont.Dispose()
    $fontFamily.Dispose()
    $borderPen.Dispose()

    if (Test-Path $frameDirectory) {
        Remove-Item -Path $frameDirectory -Recurse -Force
    }
}
