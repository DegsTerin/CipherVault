# CipherVault, auditoria criptografica e ofensiva

**Versao atual revisada:** 3.6.2**Data da revisao:** 2026-09-25

## Escopo

A revisao cobre o codigo atual e o pacote de testes. O foco foi:

- derivacao de chave;
- AES-GCM;
- salt e nonce;
- autenticacao por GCM e AAD;
- serializacao Base64 personalizada;
- validacao de entrada;
- tampering;
- exposicao no terminal e clipboard;
- abuso de recursos;
- testes e analise estatica para distribuicao publica.

Esta revisao e uma auditoria de codigo-fonte assistida, nao uma certificacao formal nem uma auditoria independente de terceira parte. A execucao dinamica deve ocorrer no ambiente Windows/PowerShell suportado pelo projeto.

## Construcao criptografica

O projeto usa AES-256-GCM com tag de 128 bits, nonce de 96 bits, salt aleatorio de 128 bits e PBKDF2-HMAC-SHA256 com 600.000 iteracoes. A chave derivada possui 256 bits.

O formato atual e exclusivamente:

```text
SC4.salt.nonce.tag.ciphertext
```

A AAD vincula versao, algoritmo e parametros do KDF.

## Testes incluidos

A suite cobre:

- reversibilidade do Base64 personalizado;
- round-trip Unicode;
- aleatoriedade observavel das mensagens geradas para o mesmo plaintext e senha;
- senha incorreta;
- alteracao de salt, tag e ciphertext;
- rejeicao de identificadores de formato nao suportados.

## Resultado atual

Os testes executados no ambiente de desenvolvimento do projeto devem ser registrados no CI e no historico do GitHub. A ausencia de findings do PSScriptAnalyzer em severidade `Error` nao substitui uma auditoria criptografica independente.

## Limitacoes conhecidas

- Senhas sao recebidas pelo PowerShell como `string`, portanto limpeza deterministica da memoria nao e garantida.
- Terminal e clipboard podem expor texto a mecanismos do sistema operacional.
- O alfabeto personalizado nao adiciona entropia nem substitui a criptografia.
- Seguranca pratica continua dependente da qualidade da senha e da integridade do endpoint.

## Recomendacao de publicacao

Antes do primeiro release publico, execute no Windows suportado:

```powershell
Invoke-ScriptAnalyzer -Path .\CipherVault.ps1 -Severity Error
Invoke-Pester .\tests
```

E preserve o resultado do CI para cada release.


## Segunda rodada ofensiva, 2026-09-25

A segunda rodada foi orientada pelo resultado real de 6/6 testes e pela revisao do caminho de entrada/saida, incluindo casos que a suite original nao cobria.

### Finding R2-01, terminal control injection em mensagens de erro, corrigido em 3.3.0

Na versao 3.1.1, alguns erros de parsing refletiam caracteres fornecidos pelo usuario diretamente na mensagem da excecao. O fluxo interativo imprimia a excecao com `Write-Host`. Um ciphertext malformado contendo ESC/CSI podia, portanto, injetar sequencias de controle no terminal durante o tratamento do erro. Isso nao quebrava AES-GCM, mas poderia alterar a tela, sobrescrever informacoes ou produzir spoofing visual em terminais ANSI.

A 3.3.0 sanitiza toda mensagem de erro antes de exibi-la e passa a reportar caracteres invalidos por code point, sem refletir o caractere bruto. Controles C0/C1, bidi e caracteres invisiveis tambem sao escapados na exibicao. PowerShell 7 e Windows Terminal suportam sequencias ANSI/VT, portanto essa camada precisa ser tratada como superficie de entrada quando texto nao confiavel e exibido.

### Finding R2-02, brute force offline por senha, risco de arquitetura

Quem obtiver um ciphertext pode testar senhas offline. Nao existe rate limit, pois nao ha servidor. O PBKDF2-HMAC-SHA256 com 600.000 iteracoes atende a referencia atual da OWASP para PBKDF2 quando FIPS-140 e um requisito, mas Argon2id e preferivel quando disponivel por ser memory-hard. A protecao pratica depende fortemente da entropia da senha.

### Finding R2-03, dependencias mutaveis no CI, risco de cadeia de suprimentos, corrigido em 3.3.0

O workflow anterior usava `actions/checkout@v4` por tag e instalava modulos por `MinimumVersion`. Tags e resolucao para versoes mais novas tornam a execucao do CI menos imutavel e menos reprodutivel. O GitHub recomenda fixar actions em SHA completo; a 3.3.0 fixa `actions/checkout` em um commit especifico e usa versoes exatas para Pester e PSScriptAnalyzer.

### Cobertura adicionada

A segunda rodada acrescenta testes para entradas malformadas, tamanho de senha, limite de plaintext, padding Base64, tamanhos de salt/nonce/tag, caracteres fora do alfabeto, campos extras, controles de terminal, Unicode bidi e fuzzing basico do parser.

### Estado

As alteracoes de 3.3.0 estao preparadas, mas os testes da nova rodada ainda precisam ser executados no Windows/PowerShell do mantenedor. O resultado anterior de 6/6 permanece valido para a 3.1.1 e foi usado como linha de base.


## Resultado da segunda rodada

A linha de base fornecida pelo mantenedor confirmou 6/6 testes, zero falhas e zero erros no Windows 11. A segunda rodada nao deve substituir esse resultado; ela o amplia.

### Exploit reproduzivel identificado na 3.1.1

Um atacante capaz de fornecer um codigo malformado podia inserir caracteres de controle terminal em um campo refletido por mensagens de erro. Exemplo conceitual: uma versao com `ESC` seguida de uma sequencia CSI. A funcao de decodificacao anterior incluia o valor recebido na excecao e o fluxo interativo o imprimia diretamente. Windows Terminal e outros hosts suportam ANSI/VT, portanto a saida de texto nao confiavel deve ser sanitizada.

### Correcao aplicada em 3.3.0

- mensagens de erro exibidas no console passam por `ConvertTo-SafeConsoleText`;
- o diagnostico de caractere invalido usa `U+XXXX` em vez de refletir o caractere bruto;
- a versao rejeitada nao e mais refletida literalmente;
- controles C0/C1, bidirecionais e invisiveis relevantes sao escapados.

### Resultado criptografico da linha de base

O relatorio do mantenedor em 2026-09-25 confirma 6 testes, todos com resultado `Success`, incluindo round-trip Unicode, ciphertext diferente em execucoes sucessivas, senha incorreta, tampering de salt/tag/ciphertext e rejeicao de formatos diferentes de SC4.

### Risco residual: senha

O principal risco criptografico residual e o ataque offline contra a senha. PBKDF2-HMAC-SHA256 com 600.000 iteracoes e uma configuracao reconhecida pela OWASP para PBKDF2 em cenarios FIPS, mas Argon2id e preferivel quando disponivel por ser memory-hard.

### Risco residual: CI e cadeia de suprimentos

A 3.3.0 fixa `actions/checkout` em SHA completo e fixa as versoes dos modulos usados nos testes. O GitHub recomenda SHA completo para actions, pois tags podem ser movidas.

### Limites da auditoria

Nao houve tentativa de quebrar AES-GCM ou PBKDF2 matematicamente. A avaliacao e de implementacao, formato, parser, superficie de terminal, memoria/recursos e cadeia de suprimentos. Nao e uma certificacao de seguranca independente.


## Terceira rodada ofensiva, 2026-09-25

### R3-01, Base64 nao canonico, baixo

Alguns decodificadores aceitam bits de padding nao-zero e, assim, mais de uma representacao textual pode produzir os mesmos bytes. A versao 3.3.0 re-encoda cada bloco e exige igualdade case-sensitive com a representacao recebida.

### R3-02, whitespace interno aceito, baixo

A versao anterior removia whitespace interno antes do parsing, permitindo representacoes textuais diferentes do mesmo codigo. A 3.3.0 aceita somente whitespace externo por `Trim()` e rejeita whitespace interno.

### R3-03, buffer da senha, baixo

`Read-PasswordHidden` usava uma lista de caracteres sem limpeza explicita do armazenamento interno. A 3.3.0 utiliza um buffer `char[]`, limpa-o no `finally` e retorna somente a string necessaria. Isso reduz a persistencia de uma copia mutavel, embora strings do PowerShell continuem gerenciadas pelo runtime.

### R3-04, instalador de dependencias, medio

O instalador local aceitava qualquer versao minima e, para Pester, usava `SkipPublisherCheck`. A 3.3.0 fixa Pester 6.2.0 e PSScriptAnalyzer 1.25.0, elimina `SkipPublisherCheck` e nao altera a politica de confianca da PSGallery.

### R3-05, sanitizacao do caminho fatal, baixo

O caminho final de excecao ainda imprimia a mensagem bruta. A 3.3.0 aplica a mesma sanitizacao de console usada nos demais fluxos. PowerShell 7 suporta sequencias ANSI/VT em terminais, portanto texto nao confiavel nao deve ser refletido sem tratamento.

### R3-06, AAD, teste adicionado

A suite ofensiva agora cria um ciphertext valido em todos os campos, mas autenticado com AAD diferente, e confirma que o CipherVault rejeita a mensagem. Isso verifica que AAD nao esta apenas documentada, mas efetivamente participa da autenticacao GCM.

### R3-07, risco residual de senha

O ataque offline de dicionario continua sendo o principal risco criptografico residual. PBKDF2-HMAC-SHA256 com 600.000 iteracoes e uma configuracao reconhecida pela OWASP quando PBKDF2 e utilizado, mas Argon2id e preferivel quando uma dependencia apropriada for aceitavel.

### R3-08, nonce por chave

O projeto usa nonce aleatorio de 96 bits e um salt aleatorio novo por mensagem, o que normalmente produz uma nova chave derivada para cada ciphertext. A exigencia de unicidade de IV do GCM continua relevante, conforme NIST SP 800-38D. A suite adiciona um teste de oito pares salt/nonce distintos por execucao.

### Supply chain residual

GitHub recomenda fixar Actions por SHA completo. O workflow ja usa SHA completo para checkout. Para releases, recomenda-se tambem assinatura de tags e artifact attestations, que permitem verificar a procedencia do artefato.


## Quarta rodada ofensiva, 2026-09-25

### R4-01, lacuna de Known Answer Tests, corrigida

As suites anteriores validavam principalmente round-trip. Isso demonstra consistencia interna, mas nao prova por si so que PBKDF2 e AES-GCM estejam produzindo valores compativeis com referencias independentes.

A 3.4.1 adiciona vetores conhecidos para PBKDF2-HMAC-SHA256 conforme RFC 7914 e AES-256-GCM conforme vetores NIST, permitindo detectar uma implementacao internamente consistente, porem algoritmicamente incorreta.

### R4-02, alocacao antes do limite de plaintext, endurecimento

A 3.3.0 convertia a string para UTF-8 antes de validar o limite em bytes. A 3.4.1 adiciona um preflight conservador pelo comprimento de caracteres antes da conversao e mantem a verificacao exata em bytes depois da conversao.

### R4-03, Unicode metamorphic testing

Foram adicionados 25 round-trips deterministas com caracteres de diferentes blocos Unicode para exercitar serializacao UTF-8 e reversibilidade fora do conjunto de testes fixos.

### Resultado

Os testes novos precisam ser executados no Windows/PowerShell suportado. A aprovacao da rodada 4 exige PSScriptAnalyzer sem erros e todos os testes Pester passando.


## Avaliacao da rodada 4

A principal lacuna identificada foi metodologica: os testes de round-trip anteriores poderiam passar mesmo se as duas pontas internas compartilhassem o mesmo erro. Known Answer Tests resolvem essa lacuna ao comparar a implementacao com vetores externos de referencia.

A rodada 4 nao introduz uma nova construcao criptografica. Ela aumenta a independencia da verificacao e reduz uma classe importante de falsos negativos nos testes.


## Correcao pos-execucao da rodada 4, 2026-09-25

A execucao local da 3.4.1 no Windows 11 produziu 35 casos, com 33 passagens e 2 falhas. As duas falhas ocorreram no codigo de teste, nao em uma tentativa de quebra do CipherVault:

1. O Known Answer Test de PBKDF2-HMAC-SHA256 utilizava o vetor RFC 7914 com `P="passwd"`, `S="salt"`, `c=1` e `dkLen=64`. O helper `Get-DerivedKey` havia imposto 16 bytes como minimo de salt, bloqueando artificialmente o vetor de 4 bytes. O RFC 7914 define o salt do vetor como uma sequencia de octetos e fornece esse valor exatamente para verificacao. A camada do formato SC4 continua exigindo salt de 16 bytes antes da derivacao da chave da aplicacao.

2. O teste de Unicode tentava converter um code point no intervalo U+1F300..U+1F64F diretamente para `System.Char`. Code points acima de U+FFFF exigem um par surrogate e devem ser convertidos como code point com `Char.ConvertFromUtf32`. O erro foi corrigido no teste.

Nenhuma dessas falhas demonstra uma vulnerabilidade no AES-256-GCM ou no formato SC4. Elas demonstram que a propria infraestrutura de verificacao precisava ser corrigida antes de usar o resultado da rodada 4 como evidencia.

A 3.4.1 preserva os parametros criptograficos da 3.4.1 e exige nova execucao completa no Windows/PowerShell do mantenedor.


## Quinta rodada ofensiva, 2026-09-25

### R5-01, identificador de formato case-insensitive, baixo, corrigido em 3.5.0

O operador `-eq` do PowerShell e case-insensitive por padrao. A versao anterior poderia aceitar `sc4` como equivalente textual de `SC4`. Isso nao alterava a construcao criptografica, pois o perfil interno continuava fixo em SC4, mas permitia mais de uma representacao textual do identificador. A 3.5.0 usa comparacao case-sensitive e adiciona teste especifico.

### R5-02, compatibilidade declarada incorreta, corrigido em 3.5.0

O codigo usa `AesGcm` com construtor que recebe explicitamente o tamanho da tag. A documentacao do .NET 8 apresenta esse construtor e recomenda indicar o tamanho requerido da tag para evitar ambiguidades de truncamento. Como PowerShell 7.4 e baseado em .NET 8, a documentacao passa a exigir PowerShell 7.4+.

### R5-03, cadeia de release, corrigido em 3.5.0

O workflow de release passa a rejeitar tags que nao sigam `vMAJOR.MINOR.PATCH`, evitando que o nome de uma tag seja usado diretamente como caminho de arquivo sem validacao.

### Testes adicionados

- rejeicao de `sc4` em vez de `SC4`;
- verificacao dos tamanhos 16/12/16 bytes;
- separacao de chave entre salts diferentes;
- senha com code point fora de U+FFFF;
- truncamento de ciphertext que permanece Base64 valido.

A rodada 5 ainda depende de execucao no ambiente Windows/PowerShell suportado antes de ser considerada aprovada.
