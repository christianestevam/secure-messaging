# Makefile para o Sistema de Mensagens Seguras

# Configurações
GO = go
BINARY_DIR = bin
SERVER_BINARY = $(BINARY_DIR)/server
CLIENT_BINARY = $(BINARY_DIR)/client
TEST_BINARY = $(BINARY_DIR)/test_crypto

# Alvos padrão
.PHONY: all build test clean run-server run-client run-tests help

all: build

# Build dos executáveis
build: $(SERVER_BINARY) $(CLIENT_BINARY) $(TEST_BINARY)

$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

$(SERVER_BINARY): $(BINARY_DIR) server.go
	$(GO) build -o $(SERVER_BINARY) server.go

$(CLIENT_BINARY): $(BINARY_DIR) client.go
	$(GO) build -o $(CLIENT_BINARY) client.go

$(TEST_BINARY): $(BINARY_DIR) test_crypto.go
	$(GO) build -o $(TEST_BINARY) test_crypto.go

# Instalar dependências
deps:
	$(GO) mod download
	$(GO) mod tidy

# Executar testes
test: $(TEST_BINARY)
	./$(TEST_BINARY)

# Executar testes com Go test
test-go:
	$(GO) test -v ./...

# Executar servidor (exemplo)
run-server: $(SERVER_BINARY)
	./$(SERVER_BINARY) bob 8080

# Executar cliente (exemplo)
run-client: $(CLIENT_BINARY)
	./$(CLIENT_BINARY) alice localhost:8080

# Executar testes criptográficos
run-tests: $(TEST_BINARY)
	./$(TEST_BINARY)

# Executar testes direto (sem build)
test-direct:
	$(GO) run test_crypto.go

# Executar servidor direto
server-direct:
	$(GO) run server.go bob 8080

# Executar cliente direto
client-direct:
	$(GO) run client.go alice localhost:8080

# Limpar arquivos gerados
clean:
	rm -rf $(BINARY_DIR)
	$(GO) clean

# Verificar formatação
fmt:
	$(GO) fmt ./...

# Verificar código
vet:
	$(GO) vet ./...

# Executar linter (requer golangci-lint)
lint:
	golangci-lint run

# Build para múltiplas plataformas
build-all: $(BINARY_DIR)
	# Linux
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BINARY_DIR)/server-linux-amd64 server.go
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BINARY_DIR)/client-linux-amd64 client.go
	
	# Windows
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BINARY_DIR)/server-windows-amd64.exe server.go
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BINARY_DIR)/client-windows-amd64.exe client.go
	
	# macOS
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BINARY_DIR)/server-darwin-amd64 server.go
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BINARY_DIR)/client-darwin-amd64 client.go

# Demo completo
demo: deps test-direct
	@echo ""
	@echo "🚀 Para testar o sistema completo:"
	@echo "   Terminal 1: make server-direct"
	@echo "   Terminal 2: make client-direct"
	@echo ""
	@echo "📋 Ou use os binários compilados:"
	@echo "   Terminal 1: make run-server"
	@echo "   Terminal 2: make run-client"

# Verificação de segurança (requer gosec)
security:
	gosec ./...

# Análise de dependências
deps-check:
	$(GO) list -m all
	$(GO) mod why -m golang.org/x/crypto

# Gerar documentação
docs:
	mkdir -p docs
	$(GO) doc -all ./crypto > docs/crypto_package.txt
	@echo "Documentação gerada em docs/crypto_package.txt"

# Benchmark (se houver testes de benchmark)
benchmark:
	$(GO) test -bench=. -benchmem ./...

# Verificar cobertura de testes
coverage:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Relatório de cobertura em coverage.html"

# Inicialização rápida
quick-start: deps test-direct
	@echo ""
	@echo "✅ Sistema pronto!"
	@echo ""
	@echo "🔥 Comandos rápidos:"
	@echo "   make demo           # Executar demo completa"
	@echo "   make server-direct  # Servidor (terminal 1)"
	@echo "   make client-direct  # Cliente (terminal 2)"

# Verificar se o projeto está funcionando
check: deps fmt vet test-direct
	@echo "✅ Verificação completa concluída!"

# Ajuda
help:
	@echo "Sistema de Mensagens Seguras - Comandos disponíveis:"
	@echo ""
	@echo "📦 Build e Dependências:"
	@echo "  deps         - Instalar/atualizar dependências"
	@echo "  build        - Compilar todos os executáveis"
	@echo "  build-all    - Build para múltiplas plataformas"
	@echo "  clean        - Limpar arquivos gerados"
	@echo ""
	@echo "🧪 Testes:"
	@echo "  test         - Executar testes (binário)"
	@echo "  test-direct  - Executar testes (direto)"
	@echo "  check        - Verificação completa"
	@echo ""
	@echo "🚀 Execução:"
	@echo "  run-server   - Executar servidor (bob:8080)"
	@echo "  run-client   - Executar cliente (alice->localhost:8080)"
	@echo "  server-direct - Servidor direto"
	@echo "  client-direct - Cliente direto"
	@echo ""
	@echo "📋 Utilitários:"
	@echo "  demo         - Demo completa"
	@echo "  quick-start  - Inicialização rápida"
	@echo "  fmt          - Formatar código"
	@echo "  vet          - Verificar código"
	@echo "  docs         - Gerar documentação"
	@echo ""
	@echo "💡 Exemplos:"
	@echo "  make quick-start             # Configurar e testar tudo"
	@echo "  make demo                    # Demo completa"
	@echo "  make server-direct & make client-direct  # Ambos em background"