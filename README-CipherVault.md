# CipherVault 3.6.2

Sistema local de criptografia de mensagens em PowerShell 7.4+, executado exclusivamente no terminal.

## Criptografia

- AES-256-GCM
- PBKDF2-HMAC-SHA256
- 600.000 iteracoes
- Salt aleatorio de 16 bytes
- Nonce aleatorio de 12 bytes
- Tag GCM de 16 bytes
- Chave derivada de 32 bytes
- AAD vinculando formato, algoritmo e parametros criptograficos

O alfabeto personalizado apenas remapeia o Base64. Ele nao aumenta a seguranca criptografica.

## Formato

O unico formato suportado e:

```text
SC4.salt.nonce.tag.ciphertext
```

Mensagens com outros identificadores de formato sao rejeitadas.

## Limites

- Senha: 12 a 256 caracteres
- Mensagem: ate 8 MiB em UTF-8
- Ciphertext: ate 8 MiB
- Texto codificado recebido: ate 16 MiB

O minimo de 12 caracteres nao garante boa entropia. Prefira senhas longas e aleatorias.

## Recursos

```text
[1] Criptografar mensagem
[2] Criptografar texto da area de transferencia
[3] Descriptografar mensagem
[4] Sobre / parametros
[0] Sair
```

Nao existem Windows Forms, WPF ou animacoes.

## Execucao

```powershell
pwsh -NoProfile -File .\CipherVault.ps1
```

Se o Windows bloquear scripts baixados, remova a marca de origem somente dos arquivos do projeto:

```powershell
Get-ChildItem -Recurse -File -Filter *.ps1 | Unblock-File
```

## Testes e analise

Instale as ferramentas de desenvolvimento:

```powershell
.\tools\Install-DevDependencies.ps1
```

Execute a verificacao completa:

```powershell
.\tools\Invoke-Checks.ps1
```

Ou execute a suite diretamente:

```powershell
Invoke-Pester .\tests
```

Apos a execucao da suite, o projeto exibe uma mensagem explicita de finalizacao dos testes.

O `Invoke-Checks.ps1` exibe ao final os contadores reais lidos do relatorio XML, por exemplo `Testes passados : 6` e `Falhas : 0`.

Para analise estatica:

```powershell
Invoke-ScriptAnalyzer -Path .\CipherVault.ps1 -Severity Error
```

## Seguranca

Nao apresente o projeto como "inquebravel", "militar" ou como auditado por terceiros sem evidencia independente.

A seguranca depende da senha e de um endpoint local nao comprometido. Terminal, clipboard, keyloggers, malware local e capturas de tela ficam fora do escopo criptografico.

Consulte `SECURITY.md` e `SECURITY-AUDIT.md`.

## CI

O GitHub Actions executa PSScriptAnalyzer e Pester em `windows-latest` a cada push e pull request.


## Auditoria ofensiva

A versao 3.3.0 inclui uma segunda rodada de testes de seguranca focada em entradas malformadas, limites de recursos, controles de terminal, Unicode invisivel/bidi e fuzzing basico do parser. Veja `SECURITY-AUDIT.md`.

Os resultados precisam ser reproduzidos no ambiente Windows/PowerShell suportado antes de qualquer release definitivo.


## Estado de seguranca

A linha de base 3.1.1 foi executada no Windows 11 com Pester 6.2.0 e PSScriptAnalyzer 1.25.0: 6 testes passaram, sem falhas ou erros. A 3.3.0 adiciona uma segunda camada de testes ofensivos e corrige uma vulnerabilidade de reflexao de caracteres de controle no caminho de erro do terminal. Consulte `SECURITY-AUDIT.md` para o escopo e as limitacoes.

## Auditoria ofensiva, rodada 3

A versao 3.4.1 amplia os testes para canonicalizacao Base64, whitespace interno, AAD, limites de entrada, aleatoriedade observavel de salt/nonce, sanitizacao adicional de Unicode e endurecimento da instalacao das ferramentas de desenvolvimento.

A versao 3.4.1 continua usando exclusivamente o formato SC4 e mantem AES-256-GCM com PBKDF2-HMAC-SHA256.


## Auditoria ofensiva, rodada 4

A 3.4.1 acrescentou testes conhecidos (KATs) independentes para PBKDF2-HMAC-SHA256 e AES-256-GCM, alem de round-trips Unicode aleatorios. A 3.4.1 corrige dois defeitos no proprio conjunto de testes revelados pela execucao da 3.4.1: o vetor RFC 7914 usa um salt de 4 bytes, enquanto a rotina interna exigia 16 bytes, e o teste Unicode tentava converter code points acima de U+FFFF diretamente para char.


### Referencias tecnicas

- RFC 7914, vetor de teste para PBKDF2-HMAC-SHA256.
- NIST SP 800-38D, GCM e requisitos de IV/nonce.
- OWASP Password Storage Cheat Sheet, parametros de PBKDF2.


## Auditoria ofensiva, rodada 5

A 3.5.0 adiciona validação case-sensitive do identificador SC4, verifica tamanhos estruturais após decodificação, testa separação de chave por salt, senha Unicode fora do BMP e truncamento de ciphertext ainda sintaticamente válido.

A 3.5.0 também declara PowerShell 7.4+ como requisito mínimo. Isso corresponde ao uso do construtor `AesGcm` que recebe explicitamente o tamanho da tag, disponível no .NET 8+, base do PowerShell 7.4.


## Modelo de ameacas

Consulte `THREAT-MODEL.md`. CipherVault protege confidencialidade e integridade, mas nao fornece autenticacao de identidade nem protecao anti-replay. A senha continua sendo o principal fator de resistencia a ataques offline.

## Auditoria ofensiva, rodada 6

A 3.6.0 consolida a revisao de modelo de ameacas e endurece a publicacao no GitHub. Foi adicionada uma auditoria de repositorio para detectar arquivos sensiveis, padroes de credenciais de alta confianca e referencias ao formato legado SC3. O workflow de release evita incluir artefatos de teste locais.


## Auditoria do repositorio, 3.6.2

`Invoke-RepositoryAudit.ps1` funciona tanto em um repositorio Git quanto em um working tree ainda nao inicializado. Em um repositorio Git, analisa os arquivos versionados. Fora do Git, analisa os arquivos locais e informa explicitamente essa limitacao.
