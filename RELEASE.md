# Release checklist

1. Execute `Get-ChildItem -Recurse -File -Filter *.ps1 | Unblock-File` quando necessário.
2. Execute `./tools/Invoke-RepositoryAudit.ps1`.
3. Execute `./tools/Invoke-Checks.ps1`.
4. Confirme `PSScriptAnalyzer : OK` e `Pester : OK`.
5. Se o projeto ainda não possuir `.git`, a auditoria funciona em modo `working tree` e informa essa limitação.
6. Após inicializar o Git, execute novamente a auditoria para verificar exatamente os arquivos versionados.
7. Crie uma tag de release assinada, por exemplo `git tag -s v3.6.2 -m "CipherVault v3.6.2"`.
8. Verifique a tag com `git tag -v v3.6.2`.
