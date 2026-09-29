Option Explicit

Dim shell
Dim fileSystem
Dim projectDirectory
Dim cipherVaultScript
Dim commandLine

Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")

projectDirectory = fileSystem.GetParentFolderName(WScript.ScriptFullName)
cipherVaultScript = fileSystem.BuildPath(projectDirectory, "CipherVault.ps1")

If Not fileSystem.FileExists(cipherVaultScript) Then
    MsgBox "CipherVault.ps1 was not found in the application folder.", vbCritical, "CipherVault"
    WScript.Quit 1
End If

commandLine = "pwsh.exe -NoProfile -File " & Chr(34) & cipherVaultScript & Chr(34)

On Error Resume Next
shell.Run commandLine, 1, False

If Err.Number <> 0 Then
    MsgBox "PowerShell 7 (pwsh.exe) could not be started." & vbCrLf & vbCrLf & _
        "Install PowerShell 7 and try again.", vbCritical, "CipherVault"
    WScript.Quit 1
End If

On Error GoTo 0

Set fileSystem = Nothing
Set shell = Nothing
