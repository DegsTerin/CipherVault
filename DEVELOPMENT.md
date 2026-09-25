# Desenvolvimento

## Ambiente

- PowerShell 7.4++
- Pester 6.2.0
- PSScriptAnalyzer 1.25.0

## Checks

```powershell
Get-ChildItem -Recurse -File -Filter *.ps1 | Unblock-File
.\tools\Invoke-Checks.ps1
```

A suite ofensiva adicional fica em `tests/CipherVault.Security.Tests.ps1`.

## Cadeia de suprimentos do CI

O workflow fixa a action de checkout por SHA completo e fixa as versoes dos modulos de teste. O Dependabot monitora atualizacoes das GitHub Actions.


## Versoes fixadas

Os checks locais e o CI usam Pester 6.2.0 e PSScriptAnalyzer 1.25.0 para tornar os resultados reproduziveis.


A rodada 4 adiciona Known Answer Tests para PBKDF2-HMAC-SHA256 e AES-256-GCM, alem de testes Unicode aleatorios.


## 3.4.1

A 3.4.1 corrige dois defeitos do conjunto de testes da 3.4.1 encontrados durante execucao real: o KAT RFC 7914 com salt curto e a geracao de Unicode suplementar.


## Auditoria do repositorio

Antes de publicar, execute:

```powershell
.\tools\Invoke-RepositoryAudit.ps1
```

A auditoria procura arquivos sensiveis, alguns padroes de credenciais de alta confianca, `test-results.xml` e referencias ao formato legado SC3. Em um repositorio Git, usa os arquivos versionados; fora do Git, analisa o working tree e informa a limitacao.
