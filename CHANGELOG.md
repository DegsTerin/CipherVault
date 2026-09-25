# Changelog

## 3.6.2
- Corrigido `Invoke-RepositoryAudit.ps1` para funcionar corretamente quando o projeto ainda não possui `.git`.
- Removido acesso inválido a `$root.Path`; a raiz agora é normalizada como caminho string.
- Cálculo de caminhos relativos feito com `[System.IO.Path]::GetRelativePath()`.
- Mantida a distinção explícita entre modo `Git repository` e `working tree`.
