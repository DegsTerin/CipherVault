# Security Policy

## Escopo

CipherVault e um aplicativo local de criptografia de mensagens. O objetivo e proteger confidencialidade e integridade contra pessoas que nao possuem a senha.

## Formato suportado

O unico formato criptografico aceito pelo aplicativo e o SC4. A versao 3.5.0 nao introduz um novo formato.

## Reporte de vulnerabilidades

Nao publique detalhes de uma vulnerabilidade exploravel em uma issue publica antes de permitir uma correcao.

Para um projeto publico no GitHub, configure o Private Vulnerability Reporting e use esse canal para reportes sensiveis.

Inclua, quando possivel:

- versao do CipherVault;
- sistema operacional;
- versao do PowerShell;
- passos para reproduzir;
- entrada ou ciphertext de teste;
- impacto observado.

## Modelo de seguranca

CipherVault assume:

- que a senha e secreta e suficientemente forte;
- que o endpoint local nao esta comprometido;
- que o usuario confere a origem dos scripts/releases;
- que clipboard e terminal podem expor informacoes conforme a configuracao do sistema.

CipherVault nao protege contra:

- keyloggers;
- malware com acesso ao processo ou memoria;
- captura de tela;
- comprometimento do sistema operacional;
- senha fraca ou reutilizada;
- vazamento voluntario da senha.

## Status de auditoria

A revisao disponivel no repositorio e uma auditoria de codigo-fonte assistida, nao uma certificacao independente. Nao use o termo "security audited" ou equivalente para representar uma auditoria de terceira parte que nao ocorreu.


## Testes de seguranca

O projeto possui testes de integridade criptografica e uma suite ofensiva adicional para parsing, limites, controles de terminal e Unicode. Resultados de uma execucao local devem ser distinguidos de uma auditoria independente.


## Publicacao e procedencia

Para releases publicas, prefira tags assinadas e publique os hashes dos artefatos. GitHub oferece verificacao de tags/commits assinados e artifact attestations para vincular um artefato ao workflow e ao commit que o produziu.


## Modelo de ameacas

Consulte `THREAT-MODEL.md` para as propriedades fornecidas e as limitacoes conhecidas, incluindo autenticacao de identidade, replay, clipboard, memoria local e ataques offline contra a senha.

Para releases publicas, recomenda-se habilitar secret scanning e push protection no repositorio. O GitHub documenta push protection como uma medida preventiva que bloqueia secrets detectados antes que cheguem ao repositorio.
