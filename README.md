# Sistema de Mensagens Seguras

Sistema de comunicação segura implementado em Go que utiliza criptografia de ponta a ponta com autenticação via GitHub.

## 📋 Descrição

Este projeto implementa um sistema completo de troca de mensagens seguras entre cliente e servidor, garantindo **confidencialidade**, **integridade** e **autenticidade** através de múltiplos algoritmos criptográficos.

### Características Principais

- 🔐 **Criptografia AES-CBC** para confidencialidade das mensagens
- 🔑 **Diffie-Hellman** para estabelecimento de chave compartilhada
- ✍️ **ECDSA** para assinaturas digitais e autenticação
- 🛡️ **HMAC-SHA256** para verificação de integridade
- 🔗 **Integração GitHub** para distribuição de chaves públicas
- 🚫 **Prevenção MITM** através de autenticação mútua

## 🏗️ Arquitetura

```
secure-messaging/
├── server.go              # Servidor principal
├── client.go              # Cliente principal
├── crypto/                # Pacote criptográfico
│   ├── ecdsa.go          # Operações ECDSA
│   ├── ssh_keys.go       # Gerenciamento GitHub/SSH
│   ├── protocol.go       # Protocolo de comunicação
│   └── ...               # Outros módulos crypto
├── keys/                  # Chaves locais
│   └── username/
│       ├── id_ecdsa      # Chave privada
│       └── id_ecdsa.pub  # Chave pública
└── README.md
```

## 🚀 Configuração e Instalação

### Pré-requisitos

- Go 1.19 ou superior
- Conta no GitHub
- Git configurado

### 1. Clone o repositório

```bash
git clone <repository-url>
cd secure-messaging
```

### 2. Instale as dependências

```bash
go mod tidy
```

### 3. Configure suas chaves ECDSA

#### Opção A: Gerar novas chaves
```bash
# Criar diretório para suas chaves
mkdir -p keys/seu_username

# Gerar par de chaves ECDSA
ssh-keygen -t ecdsa -b 256 -f keys/seu_username/id_ecdsa -N ""
```

#### Opção B: Usar chaves existentes
Copie suas chaves ECDSA existentes para `keys/seu_username/`

### 4. Adicionar chave pública ao GitHub

1. Acesse: https://github.com/settings/keys
2. Clique em "New SSH key"
3. Cole o conteúdo de `keys/seu_username/id_ecdsa.pub`
4. Salve a chave

### 5. Verificar configuração

```bash
# Testar se as chaves correspondem
curl https://github.com/seu_username.keys
```

## 💻 Como Usar

### Iniciar o Servidor

```bash
go run server.go <username> <porta>
```

**Exemplo:**
```bash
go run server.go alice 8080
```

### Conectar o Cliente

```bash
go run client.go <username> <servidor:porta>
```

**Exemplo:**
```bash
go run client.go bob localhost:8080
```

### Exemplo de Sessão Completa

**Terminal 1 (Servidor):**
```bash
$ go run server.go alice 8080
Criando servidor para alice...
Buscando chave ECDSA de 'alice' no GitHub...
Chave ECDSA encontrada no GitHub para 'alice'
Usando chave ECDSA local que corresponde ao GitHub
Servidor iniciado em :8080
Aguardando conexoes...
```

**Terminal 2 (Cliente):**
```bash
$ go run client.go bob localhost:8080
Criando cliente para bob...
Conectado ao servidor localhost:8080
Handshake concluido com sucesso!
Sessao segura estabelecida.
=== Sistema de Mensagens Seguras ===
Digite suas mensagens (ou 'quit' para sair):
> Olá Alice, esta mensagem é confidencial!
Servidor: Mensagem recebida: 'Olá Alice, esta mensagem é confidencial!'
> quit
```

## 🔧 Protocolo de Segurança

### 1. Handshake Diffie-Hellman com ECDSA

```
Cliente                               Servidor
   |                                     |
   | 1. Gera par DH (a, A=g^a mod p)     |
   | 2. Assina A+username com ECDSA      |
   |------ A, sig_A, username, salt ---->|
   |                                     | 3. Verifica sig_A via GitHub
   |                                     | 4. Gera par DH (b, B=g^b mod p)
   |                                     | 5. Assina B+username com ECDSA
   |<----- B, sig_B, username -----------|
   | 6. Verifica sig_B via GitHub        |
   | 7. Calcula S = B^a mod p            | 8. Calcula S = A^b mod p
   |                                     |
   | 9. Deriva Key_AES, Key_HMAC via PBKDF2
```

### 2. Estrutura de Mensagem Segura

```
[HMAC_TAG] + [IV_AES] + [MENSAGEM_CRIPTOGRAFADA]
    |           |              |
    |           |              └─ AES-CBC(mensagem, Key_AES, IV)
    |           └─ Initialization Vector (16 bytes)
    └─ HMAC-SHA256(IV + encrypted, Key_HMAC)
```

## 🔐 Algoritmos Criptográficos

| Componente | Algoritmo | Parâmetros |
|------------|-----------|------------|
| **Assinatura Digital** | ECDSA | Curva P-256, SHA-256 |
| **Troca de Chaves** | Diffie-Hellman | Primo 314+ bits, g=2 |
| **Derivação** | PBKDF2 | 100.000 iterações, SHA-256 |
| **Criptografia** | AES-CBC | Chaves 256-bit, IV 128-bit |
| **Integridade** | HMAC | SHA-256, chaves 256-bit |

## 🛠️ Estrutura do Código

### Componentes Principais

- **`server.go`**: Implementa servidor com handshake e processamento de mensagens
- **`client.go`**: Cliente com interface de usuário e comunicação segura
- **`crypto/ecdsa.go`**: Operações de assinatura digital ECDSA
- **`crypto/ssh_keys.go`**: Integração GitHub e gerenciamento de chaves
- **`crypto/protocol.go`**: Protocolo de comunicação segura

### Fluxo de Dados

1. **Inicialização**: Verificação de chaves locais vs GitHub
2. **Handshake**: Autenticação mútua via ECDSA + troca DH
3. **Derivação**: Geração de chaves simétricas via PBKDF2
4. **Comunicação**: Troca de mensagens com AES-CBC + HMAC

## 🔍 Troubleshooting

### Erro: "chave local não corresponde à chave do GitHub"

**Solução:**
1. Verifique se a chave no GitHub está correta
2. Confirme que a chave local existe em `keys/username/`
3. Regenere as chaves se necessário

### Erro: "erro ao buscar chave ECDSA do GitHub"

**Possíveis causas:**
- Username incorreto
- Chave não adicionada ao GitHub
- Chave não é ECDSA (deve ser `ecdsa-sha2-nistp256`)

### Timeout durante handshake

**Verificações:**
- Ambos os usuários têm chaves válidas no GitHub
- Conectividade de rede funcionando
- Portas não bloqueadas por firewall

## 📚 Referências Técnicas

- [RFC 6090 - Fundamental Elliptic Curve Cryptography Algorithms](https://tools.ietf.org/html/rfc6090)
- [RFC 2631 - Diffie-Hellman Key Agreement Method](https://tools.ietf.org/html/rfc2631)
- [RFC 2104 - HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
- [NIST SP 800-38A - AES Modes of Operation](https://csrc.nist.gov/publications/detail/sp/800-38a/final)

## 👨‍💻 Desenvolvimento

### Executar Testes

```bash
go test ./crypto/...
```

### Compilar Binários

```bash
# Servidor
go build -o bin/server server.go

# Cliente  
go build -o bin/client client.go
```

### Estrutura de Desenvolvimento

```bash
# Adicionar novos algoritmos
crypto/novo_algoritmo.go

# Testes unitários
crypto/novo_algoritmo_test.go

# Exemplos
examples/uso_exemplo.go
```

## 🤝 Contribuindo

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -am 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

---
