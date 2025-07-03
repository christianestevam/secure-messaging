package crypto

import (
	"crypto/aes"
	"crypto/ecdsa"
	"fmt"
	"math/big"
)

// ProtocolMessage representa uma mensagem do protocolo
type ProtocolMessage struct {
	Type     string                 `json:"type"`
	Username string                 `json:"username,omitempty"`
	Data     map[string]interface{} `json:"data"`
}

// HandshakeMessage representa uma mensagem de handshake
type HandshakeMessage struct {
	PublicKey *big.Int `json:"public_key"`
	Signature []byte   `json:"signature"`
	Username  string   `json:"username"`
	Salt      []byte   `json:"salt"`  // Adicionar salt ao handshake
}

// ProtocolSecureMessage representa uma mensagem segura completa com HMAC
type ProtocolSecureMessage struct {
	HMAC       []byte `json:"hmac"`
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}

// SecureSession representa uma sessão segura estabelecida
type SecureSession struct {
	AESKey       []byte
	HMACKey      []byte
	Salt         []byte
	SharedSecret *big.Int
	
	// Para criptografia
	aesEncryptor *AESEncryptor
	hmacProcessor *HMACProcessor
}

// NewSecureSession cria uma nova sessão segura
func NewSecureSession(sharedSecret *big.Int, salt []byte) (*SecureSession, error) {
	if sharedSecret == nil {
		return nil, fmt.Errorf("segredo compartilhado não pode ser nil")
	}
	
	if len(salt) == 0 {
		var err error
		salt, err = GenerateSalt(32)
		if err != nil {
			return nil, fmt.Errorf("erro ao gerar salt: %v", err)
		}
	}
	
	// Converter o segredo compartilhado para bytes
	secretBytes := sharedSecret.Bytes()
	
	// Derivar chaves usando PBKDF2
	config := DefaultPBKDF2Config()
	
	aesKey := DeriveKey(secretBytes, append(salt, []byte("AES")...), config.Iterations, 32)
	hmacKey := DeriveKey(secretBytes, append(salt, []byte("HMAC")...), config.Iterations, 32)
	
	// Criar encriptador AES
	aesEncryptor, err := NewAESEncryptor(aesKey)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar encriptador AES: %v", err)
	}
	
	// Criar processador HMAC
	hmacProcessor, err := NewHMACProcessor(hmacKey)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar processador HMAC: %v", err)
	}
	
	return &SecureSession{
		AESKey:        aesKey,
		HMACKey:       hmacKey,
		Salt:          salt,
		SharedSecret:  new(big.Int).Set(sharedSecret),
		aesEncryptor:  aesEncryptor,
		hmacProcessor: hmacProcessor,
	}, nil
}

// EncryptMessage criptografa uma mensagem
func (ss *SecureSession) EncryptMessage(plaintext []byte) (*ProtocolSecureMessage, error) {
	// Criptografar com AES
	iv, ciphertext, err := ss.aesEncryptor.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("erro ao criptografar mensagem: %v", err)
	}
	
	// Calcular HMAC de IV + ciphertext
	hmacValue := ss.hmacProcessor.ComputeMultiple(iv, ciphertext)
	
	return &ProtocolSecureMessage{
		HMAC:       hmacValue,
		IV:         iv,
		Ciphertext: ciphertext,
	}, nil
}

// DecryptMessage descriptografa uma mensagem
func (ss *SecureSession) DecryptMessage(msg *ProtocolSecureMessage) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("mensagem é nil")
	}
	
	// Verificar HMAC
	if !ss.hmacProcessor.VerifyMultiple(msg.HMAC, msg.IV, msg.Ciphertext) {
		return nil, fmt.Errorf("HMAC inválido - mensagem pode ter sido modificada")
	}
	
	// Descriptografar
	plaintext, err := ss.aesEncryptor.Decrypt(msg.Ciphertext, msg.IV)
	if err != nil {
		return nil, fmt.Errorf("erro ao descriptografar mensagem: %v", err)
	}
	
	return plaintext, nil
}

// Serialize serializa uma mensagem segura para transmissão
func (sm *ProtocolSecureMessage) Serialize() []byte {
	// Formato: [tamanho_hmac(4)][hmac][tamanho_iv(4)][iv][ciphertext]
	result := make([]byte, 8+len(sm.HMAC)+len(sm.IV)+len(sm.Ciphertext))
	offset := 0
	
	// Tamanho do HMAC (4 bytes)
	result[offset] = byte(len(sm.HMAC) >> 24)
	result[offset+1] = byte(len(sm.HMAC) >> 16)
	result[offset+2] = byte(len(sm.HMAC) >> 8)
	result[offset+3] = byte(len(sm.HMAC))
	offset += 4
	
	// HMAC
	copy(result[offset:], sm.HMAC)
	offset += len(sm.HMAC)
	
	// Tamanho do IV (4 bytes)
	result[offset] = byte(len(sm.IV) >> 24)
	result[offset+1] = byte(len(sm.IV) >> 16)
	result[offset+2] = byte(len(sm.IV) >> 8)
	result[offset+3] = byte(len(sm.IV))
	offset += 4
	
	// IV
	copy(result[offset:], sm.IV)
	offset += len(sm.IV)
	
	// Ciphertext
	copy(result[offset:], sm.Ciphertext)
	
	return result
}

// DeserializeProtocolSecureMessage deserializa uma mensagem segura
func DeserializeProtocolSecureMessage(data []byte) (*ProtocolSecureMessage, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("dados insuficientes")
	}
	
	offset := 0
	
	// Ler tamanho do HMAC
	hmacSize := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4
	
	if hmacSize <= 0 || offset+hmacSize > len(data) {
		return nil, fmt.Errorf("tamanho do HMAC inválido")
	}
	
	// Ler HMAC
	hmac := make([]byte, hmacSize)
	copy(hmac, data[offset:offset+hmacSize])
	offset += hmacSize
	
	if offset+4 > len(data) {
		return nil, fmt.Errorf("dados insuficientes para tamanho do IV")
	}
	
	// Ler tamanho do IV
	ivSize := int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	offset += 4
	
	if ivSize != aes.BlockSize || offset+ivSize > len(data) {
		return nil, fmt.Errorf("tamanho do IV inválido")
	}
	
	// Ler IV
	iv := make([]byte, ivSize)
	copy(iv, data[offset:offset+ivSize])
	offset += ivSize
	
	// Ler ciphertext
	ciphertext := make([]byte, len(data)-offset)
	copy(ciphertext, data[offset:])
	
	return &ProtocolSecureMessage{
		HMAC:       hmac,
		IV:         iv,
		Ciphertext: ciphertext,
	}, nil
}

// ProtocolHandler gerencia o protocolo de mensagens seguras
type ProtocolHandler struct {
	username     string
	ecdsaKeyPair *ECDSAKeyPair
	dhExchange   *DHExchange
	session      *SecureSession
}

// NewProtocolHandler cria um novo handler do protocolo
func NewProtocolHandler(username string) (*ProtocolHandler, error) {
	// Gerar par de chaves ECDSA
	ecdsaKeyPair, err := GenerateECDSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar chaves ECDSA: %v", err)
	}
	
	// Inicializar troca DH
	dhExchange, err := NewDHExchange(GetDefaultDHParams())
	if err != nil {
		return nil, fmt.Errorf("erro ao inicializar DH: %v", err)
	}
	
	return &ProtocolHandler{
		username:     username,
		ecdsaKeyPair: ecdsaKeyPair,
		dhExchange:   dhExchange,
	}, nil
}

// CreateHandshakeMessage cria uma mensagem de handshake
func (ph *ProtocolHandler) CreateHandshakeMessage() (*HandshakeMessage, error) {
	// Obter chave pública DH
	publicKey := ph.dhExchange.GetPublicKey()
	
	// Gerar salt para PBKDF2
	salt, err := GenerateSalt(32)
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar salt: %v", err)
	}
	
	// Criar dados para assinatura: publicKey + username + salt
	signData := append(publicKey.Bytes(), []byte(ph.username)...)
	signData = append(signData, salt...)
	
	// Assinar com ECDSA
	signature, err := SignECDSA(signData, ph.ecdsaKeyPair.Private)
	if err != nil {
		return nil, fmt.Errorf("erro ao assinar handshake: %v", err)
	}
	
	return &HandshakeMessage{
		PublicKey: publicKey,
		Signature: signature,
		Username:  ph.username,
		Salt:      salt,
	}, nil
}

// ProcessHandshakeMessage processa uma mensagem de handshake recebida
func (ph *ProtocolHandler) ProcessHandshakeMessage(msg *HandshakeMessage, otherPublicECDSAKey *ecdsa.PublicKey) error {
	// Verificar assinatura
	signData := append(msg.PublicKey.Bytes(), []byte(msg.Username)...)
	if !VerifyECDSA(signData, msg.Signature, otherPublicECDSAKey) {
		return fmt.Errorf("assinatura de handshake inválida")
	}
	
	// Definir chave pública DH do outro lado
	err := ph.dhExchange.SetOtherPublicKey(msg.PublicKey)
	if err != nil {
		return fmt.Errorf("erro ao processar chave pública DH: %v", err)
	}
	
	// Estabelecer sessão segura
	sharedSecret := ph.dhExchange.GetSharedSecret()
	ph.session, err = NewSecureSession(sharedSecret, nil)
	if err != nil {
		return fmt.Errorf("erro ao estabelecer sessão segura: %v", err)
	}
	
	return nil
}

// SendSecureMessage cria uma mensagem segura para envio
func (ph *ProtocolHandler) SendSecureMessage(plaintext []byte) (*ProtocolSecureMessage, error) {
	if ph.session == nil {
		return nil, fmt.Errorf("sessão segura não estabelecida")
	}
	
	return ph.session.EncryptMessage(plaintext)
}

// ReceiveSecureMessage processa uma mensagem segura recebida
func (ph *ProtocolHandler) ReceiveSecureMessage(msg *ProtocolSecureMessage) ([]byte, error) {
	if ph.session == nil {
		return nil, fmt.Errorf("sessão segura não estabelecida")
	}
	
	return ph.session.DecryptMessage(msg)
}

// GetECDSAPublicKey retorna a chave pública ECDSA
func (ph *ProtocolHandler) GetECDSAPublicKey() *ecdsa.PublicKey {
	return ph.ecdsaKeyPair.Public
}

// IsSessionEstablished verifica se a sessão segura foi estabelecida
func (ph *ProtocolHandler) IsSessionEstablished() bool {
	return ph.session != nil && ph.dhExchange.IsComplete()
}

// GetUsername retorna o username do handler
func (ph *ProtocolHandler) GetUsername() string {
	return ph.username
}

// GetSessionSalt retorna o salt da sessão (se estabelecida)
func (ph *ProtocolHandler) GetSessionSalt() []byte {
	if ph.session == nil {
		return nil
	}
	return ph.session.Salt
}

// Reset reinicia o handler para uma nova sessão
func (ph *ProtocolHandler) Reset() error {
	// Gerar novo par de chaves DH
	dhExchange, err := NewDHExchange(GetDefaultDHParams())
	if err != nil {
		return fmt.Errorf("erro ao reinicializar DH: %v", err)
	}
	
	ph.dhExchange = dhExchange
	ph.session = nil
	
	return nil
}

// SetOtherPublicKey define a chave pública DH do outro lado
func (ph *ProtocolHandler) SetOtherPublicKey(otherPublicKey *big.Int) error {
	return ph.dhExchange.SetOtherPublicKey(otherPublicKey)
}

// GetSharedSecret retorna o segredo compartilhado DH
func (ph *ProtocolHandler) GetSharedSecret() *big.Int {
	return ph.dhExchange.GetSharedSecret()
}

// SetSession define a sessão segura no handler
func (ph *ProtocolHandler) SetSession(session *SecureSession) {
	ph.session = session
}