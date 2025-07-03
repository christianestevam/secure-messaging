package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// GitHubKeyFetcher busca chaves públicas do GitHub
type GitHubKeyFetcher struct {
	httpClient *http.Client
}

// NewGitHubKeyFetcher cria um novo buscador de chaves
func NewGitHubKeyFetcher() *GitHubKeyFetcher {
	return &GitHubKeyFetcher{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// FetchECDSAPublicKey busca a chave pública ECDSA de um usuário GitHub
func (gkf *GitHubKeyFetcher) FetchECDSAPublicKey(username string) (*ecdsa.PublicKey, error) {
	url := fmt.Sprintf("https://github.com/%s.keys", username)
	
	resp, err := gkf.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar chaves do GitHub: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("usuário %s não encontrado no GitHub (status: %d)", username, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler resposta do GitHub: %v", err)
	}

	// Parsear chaves SSH
	publicKey, err := gkf.parseSSHECDSAKey(string(body))
	if err != nil {
		return nil, fmt.Errorf("erro ao parsear chaves SSH: %v", err)
	}

	return publicKey, nil
}

// parseSSHECDSAKey extrai chave ECDSA do formato SSH
func (gkf *GitHubKeyFetcher) parseSSHECDSAKey(keysData string) (*ecdsa.PublicKey, error) {
	lines := strings.Split(keysData, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		// Procurar por chaves ECDSA
		if strings.HasPrefix(line, "ecdsa-sha2-nistp256") {
			return gkf.parseECDSALine(line)
		}
	}
	
	return nil, fmt.Errorf("nenhuma chave ECDSA nistp256 encontrada")
}

// parseECDSALine parseia uma linha de chave ECDSA SSH
func (gkf *GitHubKeyFetcher) parseECDSALine(line string) (*ecdsa.PublicKey, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("formato de chave SSH inválido")
	}
	
	// Decodificar base64
	keyData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("erro ao decodificar base64: %v", err)
	}
	
	return gkf.parseSSHECDSAKeyData(keyData)
}

// parseSSHECDSAKeyData parseia os dados binários da chave SSH ECDSA
func (gkf *GitHubKeyFetcher) parseSSHECDSAKeyData(keyData []byte) (*ecdsa.PublicKey, error) {
	if len(keyData) < 4 {
		return nil, fmt.Errorf("dados de chave muito pequenos")
	}
	
	// Parser SSH wire format
	parser := &sshParser{data: keyData}
	
	// Ler tipo da chave
	keyType, err := parser.readString()
	if err != nil {
		return nil, fmt.Errorf("erro ao ler tipo da chave: %v", err)
	}
	
	if keyType != "ecdsa-sha2-nistp256" {
		return nil, fmt.Errorf("tipo de chave não suportado: %s", keyType)
	}
	
	// Ler nome da curva
	curveName, err := parser.readString()
	if err != nil {
		return nil, fmt.Errorf("erro ao ler nome da curva: %v", err)
	}
	
	if curveName != "nistp256" {
		return nil, fmt.Errorf("curva não suportada: %s", curveName)
	}
	
	// Ler ponto da chave pública
	publicKeyPoint, err := parser.readBytes()
	if err != nil {
		return nil, fmt.Errorf("erro ao ler ponto da chave pública: %v", err)
	}
	
	// Parsear ponto da curva elíptica (formato uncompressed)
	if len(publicKeyPoint) != 65 || publicKeyPoint[0] != 0x04 {
		return nil, fmt.Errorf("formato de ponto da chave pública inválido")
	}
	
	// Extrair coordenadas X e Y
	x := new(big.Int).SetBytes(publicKeyPoint[1:33])
	y := new(big.Int).SetBytes(publicKeyPoint[33:65])
	
	// Criar chave pública ECDSA
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	
	// Validar chave
	if err := ValidateECDSAPublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("chave pública inválida: %v", err)
	}
	
	return publicKey, nil
}

// sshParser ajuda a parsear o formato wire do SSH
type sshParser struct {
	data   []byte
	offset int
}

// readUint32 lê um uint32 em big endian
func (p *sshParser) readUint32() (uint32, error) {
	if p.offset+4 > len(p.data) {
		return 0, fmt.Errorf("dados insuficientes para uint32")
	}
	
	value := uint32(p.data[p.offset])<<24 |
		uint32(p.data[p.offset+1])<<16 |
		uint32(p.data[p.offset+2])<<8 |
		uint32(p.data[p.offset+3])
	
	p.offset += 4
	return value, nil
}

// readString lê uma string com prefixo de tamanho
func (p *sshParser) readString() (string, error) {
	length, err := p.readUint32()
	if err != nil {
		return "", err
	}
	
	if p.offset+int(length) > len(p.data) {
		return "", fmt.Errorf("dados insuficientes para string")
	}
	
	value := string(p.data[p.offset : p.offset+int(length)])
	p.offset += int(length)
	
	return value, nil
}

// readBytes lê bytes com prefixo de tamanho
func (p *sshParser) readBytes() ([]byte, error) {
	length, err := p.readUint32()
	if err != nil {
		return nil, err
	}
	
	if p.offset+int(length) > len(p.data) {
		return nil, fmt.Errorf("dados insuficientes para bytes")
	}
	
	value := make([]byte, length)
	copy(value, p.data[p.offset:p.offset+int(length)])
	p.offset += int(length)
	
	return value, nil
}

// MockGitHubKeyProvider simula chaves do GitHub para testes
type MockGitHubKeyProvider struct {
	keys map[string]*ecdsa.PublicKey
}

// NewMockGitHubKeyProvider cria um provedor mock
func NewMockGitHubKeyProvider() *MockGitHubKeyProvider {
	return &MockGitHubKeyProvider{
		keys: make(map[string]*ecdsa.PublicKey),
	}
}

// AddKey adiciona uma chave para um usuário
func (m *MockGitHubKeyProvider) AddKey(username string, publicKey *ecdsa.PublicKey) {
	m.keys[username] = publicKey
}

// FetchECDSAPublicKey busca chave do mock
func (m *MockGitHubKeyProvider) FetchECDSAPublicKey(username string) (*ecdsa.PublicKey, error) {
	key, exists := m.keys[username]
	if !exists {
		return nil, fmt.Errorf("usuário %s não encontrado no mock", username)
	}
	return key, nil
}

// KeyProvider interface para provedores de chaves
type KeyProvider interface {
	FetchECDSAPublicKey(username string) (*ecdsa.PublicKey, error)
}

// ECDSAKeyProvider é um alias para KeyProvider (para compatibilidade)
type ECDSAKeyProvider = KeyProvider

// SecureProtocolHandler versão segura com verificação de chaves
type SecureProtocolHandler struct {
	*ProtocolHandler
	keyProvider       KeyProvider
	enableVerification bool
	ecdsaPrivateKey   *ecdsa.PrivateKey  // ← CAMPO ADICIONADO
}

// NewSecureProtocolHandler cria handler seguro
func NewSecureProtocolHandler(username string, keyProvider KeyProvider) (*SecureProtocolHandler, error) {
	handler, err := NewProtocolHandler(username)
	if err != nil {
		return nil, err
	}
	
	return &SecureProtocolHandler{
		ProtocolHandler:    handler,
		keyProvider:        keyProvider,
		enableVerification: true,
		ecdsaPrivateKey:    nil,  // Será definido posteriormente
	}, nil
}

// ===== NOVOS MÉTODOS PARA ECDSA =====

// SignData assina dados usando chave ECDSA privada
func (sph *SecureProtocolHandler) SignData(data []byte) ([]byte, error) {
	// Verificar se temos uma chave privada ECDSA
	if sph.ecdsaPrivateKey == nil {
		return nil, fmt.Errorf("chave privada ECDSA não disponível")
	}
	
	// Usar a função SignECDSA existente
	return SignECDSA(data, sph.ecdsaPrivateKey)
}

// GetECDSAPrivateKey retorna a chave privada ECDSA
func (sph *SecureProtocolHandler) GetECDSAPrivateKey() *ecdsa.PrivateKey {
	return sph.ecdsaPrivateKey
}

// SetECDSAPrivateKey define a chave privada ECDSA
func (sph *SecureProtocolHandler) SetECDSAPrivateKey(privateKey *ecdsa.PrivateKey) {
	sph.ecdsaPrivateKey = privateKey
}

// LoadECDSAPrivateKeyFromFile carrega chave privada ECDSA de arquivo
func (sph *SecureProtocolHandler) LoadECDSAPrivateKeyFromFile(filename string) error {
	// Ler arquivo
	pemData, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("erro ao ler arquivo de chave: %v", err)
	}
	
	// Deserializar chave privada usando função existente
	privateKey, err := DeserializeECDSAPrivateKey(pemData)
	if err != nil {
		return fmt.Errorf("erro ao deserializar chave privada: %v", err)
	}
	
	// Definir chave privada
	sph.ecdsaPrivateKey = privateKey
	return nil
}

// NewSecureProtocolHandlerWithECDSAFile cria handler com chave ECDSA de arquivo
func NewSecureProtocolHandlerWithECDSAFile(username string, keyProvider ECDSAKeyProvider, privateKeyFile string) (*SecureProtocolHandler, error) {
	// Criar handler base
	baseHandler, err := NewProtocolHandler(username)
	if err != nil {
		return nil, err
	}
	
	// Criar handler seguro
	handler := &SecureProtocolHandler{
		ProtocolHandler:    baseHandler,
		keyProvider:        keyProvider,
		enableVerification: true,
		ecdsaPrivateKey:    nil,  // Será definido pelo LoadECDSAPrivateKeyFromFile
	}
	
	// Carregar chave privada ECDSA se arquivo fornecido
	if privateKeyFile != "" {
		err = handler.LoadECDSAPrivateKeyFromFile(privateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("erro ao carregar chave ECDSA: %v", err)
		}
	}
	
	return handler, nil
}

// ===== MÉTODOS ORIGINAIS =====

// ProcessSecureHandshakeMessage processa handshake com verificação
func (sph *SecureProtocolHandler) ProcessSecureHandshakeMessage(msg *HandshakeMessage) error {
	if sph.enableVerification && sph.keyProvider != nil {
		// Buscar chave pública do GitHub
		publicKey, err := sph.keyProvider.FetchECDSAPublicKey(msg.Username)
		if err != nil {
			return fmt.Errorf("erro ao buscar chave pública de %s: %v", msg.Username, err)
		}
		
		// Verificar assinatura
		return sph.ProcessHandshakeMessage(msg, publicKey)
	}
	
	// Fallback sem verificação
	fmt.Printf("⚠️  AVISO: Verificação de chave desabilitada para %s\n", msg.Username)
	return sph.processHandshakeWithoutVerification(msg)
}

// processHandshakeWithoutVerification processa sem verificar ECDSA
func (sph *SecureProtocolHandler) processHandshakeWithoutVerification(msg *HandshakeMessage) error {
	// Definir chave pública DH
	err := sph.dhExchange.SetOtherPublicKey(msg.PublicKey)
	if err != nil {
		return fmt.Errorf("erro ao processar chave pública DH: %v", err)
	}
	
	// Estabelecer sessão segura
	sharedSecret := sph.dhExchange.GetSharedSecret()
	sph.session, err = NewSecureSession(sharedSecret, msg.Salt)
	if err != nil {
		return fmt.Errorf("erro ao estabelecer sessão segura: %v", err)
	}
	
	return nil
}

// SetVerificationEnabled habilita/desabilita verificação
func (sph *SecureProtocolHandler) SetVerificationEnabled(enabled bool) {
	sph.enableVerification = enabled
}

// Adicione este código ao final do seu arquivo crypto/ssh_keys.go

// LocalKeyProvider busca chaves em diretórios locais
type LocalKeyProvider struct {
	keysDir string
}

// NewLocalKeyProvider cria um provedor de chaves local
func NewLocalKeyProvider(keysDir string) *LocalKeyProvider {
	if keysDir == "" {
		keysDir = "keys" // diretório padrão
	}
	return &LocalKeyProvider{
		keysDir: keysDir,
	}
}

// FetchECDSAPublicKey busca a chave pública ECDSA de um usuário local
func (lkp *LocalKeyProvider) FetchECDSAPublicKey(username string) (*ecdsa.PublicKey, error) {
	// Caminho para a chave pública do usuário
	publicKeyPath := fmt.Sprintf("%s/%s/id_ecdsa.pub", lkp.keysDir, username)
	
	// Verificar se arquivo existe
	if _, err := ioutil.ReadFile(publicKeyPath); err != nil {
		return nil, fmt.Errorf("chave pública não encontrada para usuário %s: %v", username, err)
	}
	
	// Ler chave pública SSH
	publicKeyData, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler chave pública: %v", err)
	}
	
	// Parsear chave SSH ECDSA
	return lkp.parseSSHPublicKey(string(publicKeyData))
}

// parseSSHPublicKey parseia uma chave pública SSH ECDSA
func (lkp *LocalKeyProvider) parseSSHPublicKey(keyData string) (*ecdsa.PublicKey, error) {
	keyData = strings.TrimSpace(keyData)
	
	// Verificar se é uma chave ECDSA
	if !strings.HasPrefix(keyData, "ecdsa-sha2-nistp256") {
		return nil, fmt.Errorf("chave não é ECDSA nistp256")
	}
	
	// Usar o parser existente do GitHubKeyFetcher
	gkf := &GitHubKeyFetcher{}
	return gkf.parseECDSALine(keyData)
}

// GetPrivateKeyPath retorna o caminho para a chave privada de um usuário
func (lkp *LocalKeyProvider) GetPrivateKeyPath(username string) string {
	return fmt.Sprintf("%s/%s/id_ecdsa", lkp.keysDir, username)
}

// LoadPrivateKey carrega a chave privada ECDSA de um usuário
func (lkp *LocalKeyProvider) LoadPrivateKey(username string) (*ecdsa.PrivateKey, error) {
	privateKeyPath := lkp.GetPrivateKeyPath(username)
	
	// Ler arquivo da chave privada
	pemData, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler chave privada de %s: %v", username, err)
	}
	
	// Deserializar chave privada
	privateKey, err := DeserializeECDSAPrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("erro ao deserializar chave privada: %v", err)
	}
	
	return privateKey, nil
}

// NewSecureProtocolHandlerWithLocalKeys cria handler com chaves locais
func NewSecureProtocolHandlerWithLocalKeys(username string, keysDir string) (*SecureProtocolHandler, error) {
	// Criar provedor de chaves local
	keyProvider := NewLocalKeyProvider(keysDir)
	
	// Criar handler base
	baseHandler, err := NewProtocolHandler(username)
	if err != nil {
		return nil, err
	}
	
	// Criar handler seguro
	handler := &SecureProtocolHandler{
		ProtocolHandler:    baseHandler,
		keyProvider:        keyProvider,
		enableVerification: true,
		ecdsaPrivateKey:    nil,
	}
	
	// Carregar chave privada do usuário
	privateKey, err := keyProvider.LoadPrivateKey(username)
	if err != nil {
		return nil, fmt.Errorf("erro ao carregar chave privada: %v", err)
	}
	
	handler.ecdsaPrivateKey = privateKey
	
	return handler, nil
}

// ValidateLocalKeys verifica se as chaves locais existem e são válidas
func ValidateLocalKeys(username string, keysDir string) error {
	provider := NewLocalKeyProvider(keysDir)
	
	// Verificar chave privada
	privateKey, err := provider.LoadPrivateKey(username)
	if err != nil {
		return fmt.Errorf("chave privada inválida: %v", err)
	}
	
	// Verificar chave pública
	publicKey, err := provider.FetchECDSAPublicKey(username)
	if err != nil {
		return fmt.Errorf("chave pública inválida: %v", err)
	}
	
	// Verificar se as chaves são um par válido
	if !privateKey.PublicKey.Equal(publicKey) {
		return fmt.Errorf("chave privada e pública não formam um par válido")
	}
	
	fmt.Printf("✅ Chaves válidas para usuário %s\n", username)
	return nil
}