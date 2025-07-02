package crypto

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"fmt"
	"math/big"
	"time"
)

// HandshakeData representa os dados completos de um handshake
type HandshakeData struct {
	DHPublicKey   *big.Int
	ECDSASignature []byte
	Username      string
	Salt          []byte // Para PBKDF2
}

// CreateCompleteHandshake cria um handshake completo com todos os dados necessários
func (ph *ProtocolHandler) CreateCompleteHandshake() (*HandshakeData, error) {
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
	
	return &HandshakeData{
		DHPublicKey:    publicKey,
		ECDSASignature: signature,
		Username:       ph.username,
		Salt:           salt,
	}, nil
}

// ProcessCompleteHandshake processa um handshake completo
func (ph *ProtocolHandler) ProcessCompleteHandshake(handshake *HandshakeData, otherECDSAKey *ecdsa.PublicKey) error {
	// Verificar assinatura ECDSA
	signData := append(handshake.DHPublicKey.Bytes(), []byte(handshake.Username)...)
	signData = append(signData, handshake.Salt...)
	
	if !VerifyECDSA(signData, handshake.ECDSASignature, otherECDSAKey) {
		return fmt.Errorf("assinatura ECDSA inválida")
	}
	
	// Definir chave pública DH
	err := ph.dhExchange.SetOtherPublicKey(handshake.DHPublicKey)
	if err != nil {
		return fmt.Errorf("erro ao processar chave pública DH: %v", err)
	}
	
	// Estabelecer sessão segura usando o salt do handshake
	sharedSecret := ph.dhExchange.GetSharedSecret()
	ph.session, err = NewSecureSession(sharedSecret, handshake.Salt)
	if err != nil {
		return fmt.Errorf("erro ao estabelecer sessão segura: %v", err)
	}
	
	return nil
}

// MessageEnvelope representa um envelope de mensagem com metadados
type MessageEnvelope struct {
	Timestamp   int64                    `json:"timestamp"`
	MessageType string                   `json:"message_type"`
	Sender      string                   `json:"sender"`
	Content     *ProtocolSecureMessage   `json:"content"`
}

// CreateMessageEnvelope cria um envelope para uma mensagem
func (ph *ProtocolHandler) CreateMessageEnvelope(messageType string, plaintext []byte) (*MessageEnvelope, error) {
	if ph.session == nil {
		return nil, fmt.Errorf("sessão segura não estabelecida")
	}
	
	// Criptografar conteúdo
	secureMsg, err := ph.session.EncryptMessage(plaintext)
	if err != nil {
		return nil, fmt.Errorf("erro ao criptografar mensagem: %v", err)
	}
	
	return &MessageEnvelope{
		Timestamp:   time.Now().Unix(),
		MessageType: messageType,
		Sender:      ph.username,
		Content:     secureMsg,
	}, nil
}

// ProcessMessageEnvelope processa um envelope de mensagem recebido
func (ph *ProtocolHandler) ProcessMessageEnvelope(envelope *MessageEnvelope) ([]byte, error) {
	if ph.session == nil {
		return nil, fmt.Errorf("sessão segura não estabelecida")
	}
	
	// Descriptografar conteúdo
	plaintext, err := ph.session.DecryptMessage(envelope.Content)
	if err != nil {
		return nil, fmt.Errorf("erro ao descriptografar mensagem: %v", err)
	}
	
	return plaintext, nil
}

// KeyExchangeStatus representa o status da troca de chaves
type KeyExchangeStatus struct {
	DHComplete      bool   `json:"dh_complete"`
	SessionActive   bool   `json:"session_active"`
	Username        string `json:"username"`
	SharedSecretSet bool   `json:"shared_secret_set"`
}

// GetKeyExchangeStatus retorna o status atual da troca de chaves
func (ph *ProtocolHandler) GetKeyExchangeStatus() *KeyExchangeStatus {
	return &KeyExchangeStatus{
		DHComplete:      ph.dhExchange.IsComplete(),
		SessionActive:   ph.session != nil,
		Username:        ph.username,
		SharedSecretSet: ph.dhExchange.GetSharedSecret() != nil,
	}
}

// SecureChannel representa um canal de comunicação seguro
type SecureChannel struct {
	localHandler  *ProtocolHandler
	remoteHandler *ProtocolHandler
	isServer      bool
}

// NewSecureChannel cria um novo canal seguro
func NewSecureChannel(localUsername string, isServer bool) (*SecureChannel, error) {
	handler, err := NewProtocolHandler(localUsername)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar handler local: %v", err)
	}
	
	return &SecureChannel{
		localHandler: handler,
		isServer:     isServer,
	}, nil
}

// EstablishChannel estabelece o canal seguro com o peer
func (sc *SecureChannel) EstablishChannel(remoteUsername string, remoteDHPublicKey *big.Int, remoteECDSAKey *ecdsa.PublicKey, remoteSignature []byte) error {
	// Verificar e processar handshake remoto
	remoteHandshake := &HandshakeMessage{
		PublicKey: remoteDHPublicKey,
		Signature: remoteSignature,
		Username:  remoteUsername,
	}
	
	err := sc.localHandler.ProcessHandshakeMessage(remoteHandshake, remoteECDSAKey)
	if err != nil {
		return fmt.Errorf("erro ao processar handshake remoto: %v", err)
	}
	
	return nil
}

// SendMessage envia uma mensagem segura através do canal
func (sc *SecureChannel) SendMessage(message []byte) (*ProtocolSecureMessage, error) {
	return sc.localHandler.SendSecureMessage(message)
}

// ReceiveMessage recebe e descriptografa uma mensagem
func (sc *SecureChannel) ReceiveMessage(secureMsg *ProtocolSecureMessage) ([]byte, error) {
	return sc.localHandler.ReceiveSecureMessage(secureMsg)
}

// IsEstablished verifica se o canal está estabelecido
func (sc *SecureChannel) IsEstablished() bool {
	return sc.localHandler.IsSessionEstablished()
}

// GetLocalPublicKey retorna a chave pública ECDSA local
func (sc *SecureChannel) GetLocalPublicKey() *ecdsa.PublicKey {
	return sc.localHandler.GetECDSAPublicKey()
}

// ProtocolVersion representa a versão do protocolo
type ProtocolVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Patch int `json:"patch"`
}

// CurrentProtocolVersion é a versão atual do protocolo
var CurrentProtocolVersion = ProtocolVersion{
	Major: 1,
	Minor: 0,
	Patch: 0,
}

// ProtocolInfo contém informações sobre o protocolo
type ProtocolInfo struct {
	Version     ProtocolVersion `json:"version"`
	Algorithms  []string        `json:"algorithms"`
	KeySizes    map[string]int  `json:"key_sizes"`
	Description string          `json:"description"`
}

// GetProtocolInfo retorna informações sobre o protocolo implementado
func GetProtocolInfo() *ProtocolInfo {
	return &ProtocolInfo{
		Version: CurrentProtocolVersion,
		Algorithms: []string{
			"Diffie-Hellman",
			"ECDSA (P-256)",
			"AES-256-CBC",
			"HMAC-SHA256",
			"PBKDF2",
		},
		KeySizes: map[string]int{
			"DH":     2048,
			"ECDSA":  256,
			"AES":    256,
			"HMAC":   256,
			"PBKDF2": 256,
		},
		Description: "Sistema de mensagens seguras com DH + ECDSA + AES + HMAC",
	}
}

// SecurityLevel representa o nível de segurança
type SecurityLevel int

const (
	SecurityLevelLow SecurityLevel = iota
	SecurityLevelMedium
	SecurityLevelHigh
	SecurityLevelMaximum
)

// GetSecurityLevel retorna o nível de segurança atual
func (ph *ProtocolHandler) GetSecurityLevel() SecurityLevel {
	if ph.session == nil {
		return SecurityLevelLow
	}
	
	// Verificar configurações de segurança
	if len(ph.session.AESKey) >= 32 && len(ph.session.HMACKey) >= 32 {
		return SecurityLevelHigh
	} else if len(ph.session.AESKey) >= 24 {
		return SecurityLevelMedium
	}
	
	return SecurityLevelLow
}

// ValidateProtocolSecurity valida a segurança do protocolo
func ValidateProtocolSecurity(handler *ProtocolHandler) error {
	if !handler.IsSessionEstablished() {
		return fmt.Errorf("sessão não estabelecida")
	}
	
	level := handler.GetSecurityLevel()
	if level < SecurityLevelMedium {
		return fmt.Errorf("nível de segurança insuficiente")
	}
	
	// Verificar se as chaves são diferentes
	if subtle.ConstantTimeCompare(handler.session.AESKey, handler.session.HMACKey) == 1 {
		return fmt.Errorf("chaves AES e HMAC são idênticas - falha na derivação")
	}
	
	return nil
}

// Função adicional para validar mensagens
func ValidateMessageIntegrity(iv, ciphertext, hmac, hmacKey []byte) bool {
	processor, err := NewHMACProcessor(hmacKey)
	if err != nil {
		return false
	}
	
	return processor.VerifyMultiple(hmac, iv, ciphertext)
}

// Função para gerar identificador único de sessão
func GenerateSessionID() string {
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}

// Estrutura para estatísticas da sessão
type SessionStats struct {
	MessagesEncrypted int64     `json:"messages_encrypted"`
	MessagesDecrypted int64     `json:"messages_decrypted"`
	BytesEncrypted    int64     `json:"bytes_encrypted"`
	BytesDecrypted    int64     `json:"bytes_decrypted"`
	SessionStartTime  time.Time `json:"session_start_time"`
	LastActivity      time.Time `json:"last_activity"`
}

// Adicionar estatísticas à SecureSession
func (ss *SecureSession) GetStats() *SessionStats {
	return &SessionStats{
		MessagesEncrypted: 0, // Implementar contadores
		MessagesDecrypted: 0,
		BytesEncrypted:    0,
		BytesDecrypted:    0,
		SessionStartTime:  time.Now(), // Deveria ser armazenado na criação
		LastActivity:      time.Now(),
	}
}

// Função para limpar dados sensíveis da memória
func (ss *SecureSession) ClearSensitiveData() {
	if ss.AESKey != nil {
		for i := range ss.AESKey {
			ss.AESKey[i] = 0
		}
	}
	
	if ss.HMACKey != nil {
		for i := range ss.HMACKey {
			ss.HMACKey[i] = 0
		}
	}
	
	if ss.Salt != nil {
		for i := range ss.Salt {
			ss.Salt[i] = 0
		}
	}
	
	// Limpar shared secret
	if ss.SharedSecret != nil {
		ss.SharedSecret.SetInt64(0)
	}
}

// Função auxiliar para debug (remover em produção)
func (ph *ProtocolHandler) DebugInfo() map[string]interface{} {
	info := make(map[string]interface{})
	
	info["username"] = ph.username
	info["dh_complete"] = ph.dhExchange.IsComplete()
	info["session_established"] = ph.session != nil
	
	if ph.session != nil {
		info["aes_key_size"] = len(ph.session.AESKey)
		info["hmac_key_size"] = len(ph.session.HMACKey)
		info["salt_size"] = len(ph.session.Salt)
	}
	
	return info
}