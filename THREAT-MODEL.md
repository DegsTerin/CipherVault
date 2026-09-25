# CipherVault Threat Model

## Objetivo

Proteger confidencialidade e integridade de mensagens contra um atacante que conhece o formato do CipherVault e possui o ciphertext, mas nao possui a senha.

## Atacante coberto

- Obtem ciphertexts armazenados ou interceptados.
- Conhece o codigo-fonte e os parametros publicos.
- Pode alterar bytes do ciphertext.
- Pode tentar senhas offline.
- Pode fornecer entradas malformadas ao parser.

## Atacante nao coberto

- Malware com acesso ao processo, memoria ou teclado.
- Keylogger.
- Captura de tela.
- Comprometimento do sistema operacional.
- Controle do ambiente GitHub/release.
- Comprometimento do host durante a execucao.

## Propriedades fornecidas

- Confidencialidade do plaintext sob a seguranca da senha e do AES-256-GCM.
- Integridade e autenticacao do ciphertext e da AAD.
- Novas mensagens usam salt e nonce aleatorios.
- O formato SC4 vincula a versao e parametros criptograficos por AAD.

## Propriedades nao fornecidas

### Autenticacao de identidade

AES-GCM autentica a mensagem para quem possui a chave derivada, mas nao prova qual pessoa a produziu. Compartilhar a mesma senha significa compartilhar a capacidade de produzir mensagens validas.

### Anti-replay

O CipherVault nao mantem estado para impedir que um ciphertext autentico seja reapresentado. Se o contexto exigir anti-replay, o protocolo precisa de estado ou de um mecanismo de sequenciamento externo.

### Resistência a senhas fracas

A derivacao usa PBKDF2-HMAC-SHA256 com 600.000 iteracoes. Isso aumenta o custo das tentativas, mas nao transforma uma senha humana fraca em uma senha forte. A OWASP recomenda 600.000 iteracoes para PBKDF2-HMAC-SHA256 quando PBKDF2 e necessario, e prefere Argon2id quando disponivel.

### Exposicao local

O aplicativo usa strings do PowerShell para plaintext e senha em algumas etapas. O runtime gerenciado nao oferece apagamento deterministico de todas as copias dessas strings.

### Clipboard

O ciphertext pode ser copiado automaticamente para o clipboard. O ciphertext nao e secreto por si so, mas pode ser sincronizado ou observado por outros aplicativos conforme a configuracao do sistema.

## Consideracoes sobre GCM

O nonce de 96 bits e gerado pelo CSPRNG. O NIST estabelece como requisito critico que IVs/nonce nao sejam repetidos para a mesma chave e recomenda 96 bits para simplicidade e eficiencia.

## Decisao de arquitetura

CipherVault permanece deliberadamente sem dependencias criptograficas externas. Isso reduz a superficie de supply chain, mas significa que PBKDF2 continua sendo o KDF disponivel para derivar a chave a partir de senha.
