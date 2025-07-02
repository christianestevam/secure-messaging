package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// HMACConfig configuração para HMAC
type HMACConfig struct {
	KeySize int // Tamanho da chave em bytes
}

// DefaultHMACConfig retorna configuração padrão para HMAC
func DefaultHMACConfig() *HMACConfig {
	return &HMACConfig{
		KeySize: 32, // 256 bits
	}
}

// ComputeHMAC calcula HMAC-SHA256 de dados com uma chave
func ComputeHMAC(data, key []byte) []byte {
	if len(key) == 0 {
		panic("chave HMAC não pode ser vazia")
	}
	
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC verifica se um HMAC é válido
func VerifyHMAC(data, key, expectedHMAC []byte) bool {
	if len(key) == 0 || len(expectedHMAC) == 0 {
		return false
	}
	
	computedHMAC := ComputeHMAC(data, key)
	
	// Comparação em tempo constante para prevenir ataques de temporização
	return subtle.ConstantTimeCompare(computedHMAC, expectedHMAC) == 1
}

// ComputeHMACMultiple calcula HMAC de múltiplos dados concatenados
func ComputeHMACMultiple(key []byte, dataList ...[]byte) []byte {
	if len(key) == 0 {
		panic("chave HMAC não pode ser vazia")
	}
	
	h := hmac.New(sha256.New, key)
	
	for _, data := range dataList {
		h.Write(data)
	}
	
	return h.Sum(nil)
}

// VerifyHMACMultiple verifica HMAC de múltiplos dados concatenados
func VerifyHMACMultiple(key, expectedHMAC []byte, dataList ...[]byte) bool {
	if len(key) == 0 || len(expectedHMAC) == 0 {
		return false
	}
	
	computedHMAC := ComputeHMACMultiple(key, dataList...)
	
	return subtle.ConstantTimeCompare(computedHMAC, expectedHMAC) == 1
}

// HMACProcessor representa um processador HMAC
type HMACProcessor struct {
	key []byte
}

// NewHMACProcessor cria um novo processador HMAC
func NewHMACProcessor(key []byte) (*HMACProcessor, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("chave HMAC não pode ser vazia")
	}
	
	// Fazer uma cópia da chave para segurança
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	
	return &HMACProcessor{
		key: keyCopy,
	}, nil
}

// Compute calcula HMAC dos dados
func (hp *HMACProcessor) Compute(data []byte) []byte {
	return ComputeHMAC(data, hp.key)
}

// ComputeMultiple calcula HMAC de múltiplos dados
func (hp *HMACProcessor) ComputeMultiple(dataList ...[]byte) []byte {
	return ComputeHMACMultiple(hp.key, dataList...)
}

// Verify verifica se um HMAC é válido
func (hp *HMACProcessor) Verify(data, expectedHMAC []byte) bool {
	return VerifyHMAC(data, hp.key, expectedHMAC)
}

// VerifyMultiple verifica HMAC de múltiplos dados
func (hp *HMACProcessor) VerifyMultiple(expectedHMAC []byte, dataList ...[]byte) bool {
	return VerifyHMACMultiple(hp.key, expectedHMAC, dataList...)
}

// GetKeySize retorna o tamanho da chave
func (hp *HMACProcessor) GetKeySize() int {
	return len(hp.key)
}

// AuthenticatedMessage representa uma mensagem com HMAC
type AuthenticatedMessage struct {
	Data []byte
	HMAC []byte
}

// NewAuthenticatedMessage cria uma nova mensagem autenticada
func NewAuthenticatedMessage(data, key []byte) *AuthenticatedMessage {
	hmacValue := ComputeHMAC(data, key)
	
	return &AuthenticatedMessage{
		Data: data,
		HMAC: hmacValue,
	}
}

// Verify verifica a autenticidade da mensagem
func (am *AuthenticatedMessage) Verify(key []byte) bool {
	return VerifyHMAC(am.Data, key, am.HMAC)
}

// Serialize serializa a mensagem autenticada
func (am *AuthenticatedMessage) Serialize() []byte {
	// Formato: [tamanho_hmac][hmac][data]
	result := make([]byte, 4+len(am.HMAC)+len(am.Data))
	
	// Tamanho do HMAC (4 bytes)
	result[0] = byte(len(am.HMAC) >> 24)
	result[1] = byte(len(am.HMAC) >> 16)
	result[2] = byte(len(am.HMAC) >> 8)
	result[3] = byte(len(am.HMAC))
	
	// HMAC
	copy(result[4:4+len(am.HMAC)], am.HMAC)
	
	// Dados
	copy(result[4+len(am.HMAC):], am.Data)
	
	return result
}

// DeserializeAuthenticatedMessage deserializa uma mensagem autenticada
func DeserializeAuthenticatedMessage(serialized []byte) (*AuthenticatedMessage, error) {
	if len(serialized) < 4 {
		return nil, fmt.Errorf("dados muito pequenos para conter tamanho do HMAC")
	}
	
	// Ler tamanho do HMAC
	hmacSize := int(serialized[0])<<24 | int(serialized[1])<<16 | int(serialized[2])<<8 | int(serialized[3])
	
	if hmacSize <= 0 || hmacSize > len(serialized)-4 {
		return nil, fmt.Errorf("tamanho do HMAC inválido: %d", hmacSize)
	}
	
	if len(serialized) < 4+hmacSize {
		return nil, fmt.Errorf("dados insuficientes para conter HMAC")
	}
	
	// Extrair HMAC e dados
	hmacValue := make([]byte, hmacSize)
	copy(hmacValue, serialized[4:4+hmacSize])
	
	data := make([]byte, len(serialized)-4-hmacSize)
	copy(data, serialized[4+hmacSize:])
	
	return &AuthenticatedMessage{
		Data: data,
		HMAC: hmacValue,
	}, nil
}

// SecureMessageValidator valida mensagens com HMAC
type SecureMessageValidator struct {
	processor *HMACProcessor
}

// NewSecureMessageValidator cria um novo validador
func NewSecureMessageValidator(key []byte) (*SecureMessageValidator, error) {
	processor, err := NewHMACProcessor(key)
	if err != nil {
		return nil, err
	}
	
	return &SecureMessageValidator{
		processor: processor,
	}, nil
}

// ValidateMessage valida uma mensagem com IV e ciphertext
func (smv *SecureMessageValidator) ValidateMessage(iv, ciphertext, receivedHMAC []byte) bool {
	return smv.processor.VerifyMultiple(receivedHMAC, iv, ciphertext)
}

// GenerateMessageHMAC gera HMAC para uma mensagem com IV e ciphertext
func (smv *SecureMessageValidator) GenerateMessageHMAC(iv, ciphertext []byte) []byte {
	return smv.processor.ComputeMultiple(iv, ciphertext)
}

// ConstantTimeHMACCompare compara dois HMACs em tempo constante
func ConstantTimeHMACCompare(hmac1, hmac2 []byte) bool {
	return subtle.ConstantTimeCompare(hmac1, hmac2) == 1
}