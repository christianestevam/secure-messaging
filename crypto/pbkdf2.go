package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2Config configuração para derivação de chaves PBKDF2
type PBKDF2Config struct {
	Iterations int    // Número de iterações (recomendado: >= 100.000)
	SaltSize   int    // Tamanho do salt em bytes (recomendado: >= 16)
	KeyLength  int    // Tamanho da chave derivada em bytes
}

// DefaultPBKDF2Config retorna configuração padrão segura
func DefaultPBKDF2Config() *PBKDF2Config {
	return &PBKDF2Config{
		Iterations: 100000, // 100k iterações
		SaltSize:   32,     // 32 bytes de salt
		KeyLength:  32,     // 32 bytes de chave (256 bits)
	}
}

// SecurePBKDF2Config retorna configuração mais segura (mais lenta)
func SecurePBKDF2Config() *PBKDF2Config {
	return &PBKDF2Config{
		Iterations: 500000, // 500k iterações
		SaltSize:   64,     // 64 bytes de salt
		KeyLength:  32,     // 32 bytes de chave
	}
}

// DeriveKey deriva uma chave usando PBKDF2 com SHA-256
func DeriveKey(password, salt []byte, iterations, keyLength int) []byte {
	if iterations <= 0 {
		panic("número de iterações deve ser positivo")
	}
	if keyLength <= 0 {
		panic("tamanho da chave deve ser positivo")
	}
	
	return pbkdf2.Key(password, salt, iterations, keyLength, sha256.New)
}

// DeriveKeyWithConfig deriva uma chave usando configuração PBKDF2
func DeriveKeyWithConfig(password, salt []byte, config *PBKDF2Config) []byte {
	if config == nil {
		config = DefaultPBKDF2Config()
	}
	
	return DeriveKey(password, salt, config.Iterations, config.KeyLength)
}

// DeriveKeys deriva múltiplas chaves diferentes a partir de um segredo
func DeriveKeys(secret, salt []byte, iterations int) (aesKey, hmacKey []byte) {
	// Derivar chave AES (32 bytes para AES-256)
	aesKey = DeriveKey(secret, append(salt, []byte("AES")...), iterations, 32)
	
	// Derivar chave HMAC (32 bytes para HMAC-SHA256)
	hmacKey = DeriveKey(secret, append(salt, []byte("HMAC")...), iterations, 32)
	
	return aesKey, hmacKey
}

// DeriveMultipleKeys deriva múltiplas chaves com diferentes contextos
func DeriveMultipleKeys(secret, salt []byte, contexts []string, iterations, keyLength int) map[string][]byte {
	keys := make(map[string][]byte)
	
	for _, context := range contexts {
		contextSalt := append(salt, []byte(context)...)
		keys[context] = DeriveKey(secret, contextSalt, iterations, keyLength)
	}
	
	return keys
}

// GenerateSalt gera um salt aleatório
func GenerateSalt(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("tamanho do salt deve ser positivo")
	}
	
	if size < 16 {
		fmt.Printf("Aviso: salt pequeno (recomendado >= 16 bytes): %d\n", size)
	}
	
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("erro ao gerar salt: %v", err)
	}
	
	return salt, nil
}

// KeyDerivationResult resultado da derivação de chaves
type KeyDerivationResult struct {
	AESKey  []byte
	HMACKey []byte
	Salt    []byte
	Config  *PBKDF2Config
}

// DeriveSessionKeys deriva chaves de sessão a partir de um segredo compartilhado
func DeriveSessionKeys(sharedSecret, salt []byte, config *PBKDF2Config) *KeyDerivationResult {
	if config == nil {
		config = DefaultPBKDF2Config()
	}
	
	aesKey, hmacKey := DeriveKeys(sharedSecret, salt, config.Iterations)
	
	return &KeyDerivationResult{
		AESKey:  aesKey,
		HMACKey: hmacKey,
		Salt:    salt,
		Config:  config,
	}
}

// DeriveSessionKeysWithNewSalt deriva chaves com salt novo
func DeriveSessionKeysWithNewSalt(sharedSecret []byte, config *PBKDF2Config) (*KeyDerivationResult, error) {
	if config == nil {
		config = DefaultPBKDF2Config()
	}
	
	salt, err := GenerateSalt(config.SaltSize)
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar salt: %v", err)
	}
	
	return DeriveSessionKeys(sharedSecret, salt, config), nil
}

// ValidateConfig valida uma configuração PBKDF2
func (config *PBKDF2Config) Validate() error {
	if config.Iterations < 10000 {
		return fmt.Errorf("número de iterações muito baixo (mínimo: 10.000)")
	}
	
	if config.SaltSize < 16 {
		return fmt.Errorf("tamanho do salt muito pequeno (mínimo: 16 bytes)")
	}
	
	if config.KeyLength <= 0 {
		return fmt.Errorf("tamanho da chave deve ser positivo")
	}
	
	return nil
}

// PBKDF2Deriver representa um derivador de chaves PBKDF2
type PBKDF2Deriver struct {
	config *PBKDF2Config
}

// NewPBKDF2Deriver cria um novo derivador PBKDF2
func NewPBKDF2Deriver(config *PBKDF2Config) (*PBKDF2Deriver, error) {
	if config == nil {
		config = DefaultPBKDF2Config()
	}
	
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuração inválida: %v", err)
	}
	
	return &PBKDF2Deriver{
		config: config,
	}, nil
}

// DeriveKey deriva uma chave usando a configuração do derivador
func (pd *PBKDF2Deriver) DeriveKey(password, salt []byte) []byte {
	return DeriveKey(password, salt, pd.config.Iterations, pd.config.KeyLength)
}

// DeriveMultipleKeys deriva múltiplas chaves
func (pd *PBKDF2Deriver) DeriveMultipleKeys(password, salt []byte, contexts []string) map[string][]byte {
	return DeriveMultipleKeys(password, salt, contexts, pd.config.Iterations, pd.config.KeyLength)
}

// DeriveSessionKeys deriva chaves de sessão
func (pd *PBKDF2Deriver) DeriveSessionKeys(sharedSecret, salt []byte) *KeyDerivationResult {
	return DeriveSessionKeys(sharedSecret, salt, pd.config)
}

// GetConfig retorna a configuração do derivador
func (pd *PBKDF2Deriver) GetConfig() *PBKDF2Config {
	return pd.config
}

// SecureKeyDerivation representa uma derivação de chave segura completa
type SecureKeyDerivation struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	DerivedKey []byte
}

// NewSecureKeyDerivation cria uma nova derivação de chave segura
func NewSecureKeyDerivation(password []byte, config *PBKDF2Config) (*SecureKeyDerivation, error) {
	if config == nil {
		config = DefaultPBKDF2Config()
	}
	
	salt, err := GenerateSalt(config.SaltSize)
	if err != nil {
		return nil, err
	}
	
	derivedKey := DeriveKey(password, salt, config.Iterations, config.KeyLength)
	
	return &SecureKeyDerivation{
		Salt:       salt,
		Iterations: config.Iterations,
		KeyLength:  config.KeyLength,
		DerivedKey: derivedKey,
	}, nil
}

// Verify verifica se uma senha produz a mesma chave derivada
func (skd *SecureKeyDerivation) Verify(password []byte) bool {
	testKey := DeriveKey(password, skd.Salt, skd.Iterations, skd.KeyLength)
	
	// Comparação em tempo constante
	return subtle.ConstantTimeCompare(skd.DerivedKey, testKey) == 1
}