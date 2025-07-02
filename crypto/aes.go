package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// AESEncryptor representa um encriptador AES
type AESEncryptor struct {
	key []byte
}

// NewAESEncryptor cria um novo encriptador AES
func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	if err := validateAESKey(key); err != nil {
		return nil, err
	}

	return &AESEncryptor{
		key: key,
	}, nil
}

// EncryptAES criptografa dados usando AES-256-CBC
func EncryptAES(plaintext, key []byte) (iv, ciphertext []byte, err error) {
	if err := validateAESKey(key); err != nil {
		return nil, nil, err
	}

	if len(plaintext) == 0 {
		return nil, nil, fmt.Errorf("texto plano não pode ser vazio")
	}

	// Criar cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("erro ao criar cipher AES: %v", err)
	}

	// Gerar IV aleatório
	iv = make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("erro ao gerar IV: %v", err)
	}

	// Aplicar padding PKCS7
	paddedPlaintext := pkcs7Pad(plaintext, aes.BlockSize)

	// Criptografar usando CBC
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext = make([]byte, len(paddedPlaintext))
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return iv, ciphertext, nil
}

// DecryptAES descriptografa dados usando AES-256-CBC
func DecryptAES(ciphertext, key, iv []byte) ([]byte, error) {
	if err := validateAESKey(key); err != nil {
		return nil, err
	}

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("texto cifrado não pode ser vazio")
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV deve ter %d bytes, recebido: %d", aes.BlockSize, len(iv))
	}

	// Verificar se o tamanho do ciphertext é múltiplo do block size
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("texto cifrado deve ser múltiplo do block size (%d)", aes.BlockSize)
	}

	// Criar cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar cipher AES: %v", err)
	}

	// Descriptografar usando CBC
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remover padding PKCS7
	unpaddedPlaintext, err := pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("erro ao remover padding: %v", err)
	}

	return unpaddedPlaintext, nil
}

// Encrypt criptografa dados usando a chave do encriptador
func (enc *AESEncryptor) Encrypt(plaintext []byte) (iv, ciphertext []byte, err error) {
	return EncryptAES(plaintext, enc.key)
}

// Decrypt descriptografa dados usando a chave do encriptador
func (enc *AESEncryptor) Decrypt(ciphertext, iv []byte) ([]byte, error) {
	return DecryptAES(ciphertext, enc.key, iv)
}

// pkcs7Pad adiciona padding PKCS7 ao dados
func pkcs7Pad(data []byte, blockSize int) []byte {
	if blockSize <= 0 || blockSize > 255 {
		panic("blockSize deve estar entre 1 e 255")
	}

	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// pkcs7Unpad remove padding PKCS7 dos dados
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, ErrInvalidPadding
	}

	padding := int(data[length-1])
	
	// Validar padding
	if padding > length || padding == 0 {
		return nil, ErrInvalidPadding
	}

	// Verificar se todos os bytes de padding são iguais
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, ErrInvalidPadding
		}
	}

	return data[:length-padding], nil
}

// validateAESKey valida uma chave AES
func validateAESKey(key []byte) error {
	switch len(key) {
	case 16, 24, 32: // AES-128, AES-192, AES-256
		return nil
	default:
		return fmt.Errorf("chave AES deve ter 16, 24 ou 32 bytes, recebido: %d", len(key))
	}
}

// GenerateAESKey gera uma chave AES aleatória
func GenerateAESKey(keySize int) ([]byte, error) {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, fmt.Errorf("tamanho de chave inválido: %d", keySize)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("erro ao gerar chave AES: %v", err)
	}

	return key, nil
}

// EncryptMessage criptografa uma mensagem e retorna o resultado concatenado
func EncryptMessage(message, key []byte) ([]byte, error) {
	iv, ciphertext, err := EncryptAES(message, key)
	if err != nil {
		return nil, err
	}

	// Concatenar IV + ciphertext
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:len(iv)], iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

// DecryptMessage descriptografa uma mensagem do formato concatenado
func DecryptMessage(encryptedData, key []byte) ([]byte, error) {
	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("dados criptografados muito pequenos")
	}

	// Extrair IV e ciphertext
	iv := encryptedData[:aes.BlockSize]
	ciphertext := encryptedData[aes.BlockSize:]

	return DecryptAES(ciphertext, key, iv)
}

// SecureMessage representa uma mensagem criptografada de forma segura
type SecureMessage struct {
	IV         []byte
	Ciphertext []byte
}

// NewSecureMessage cria uma nova mensagem segura
func NewSecureMessage(plaintext, key []byte) (*SecureMessage, error) {
	iv, ciphertext, err := EncryptAES(plaintext, key)
	if err != nil {
		return nil, err
	}

	return &SecureMessage{
		IV:         iv,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt descriptografa a mensagem segura
func (sm *SecureMessage) Decrypt(key []byte) ([]byte, error) {
	return DecryptAES(sm.Ciphertext, key, sm.IV)
}

// Serialize serializa a mensagem segura para bytes
func (sm *SecureMessage) Serialize() []byte {
	result := make([]byte, len(sm.IV)+len(sm.Ciphertext))
	copy(result[:len(sm.IV)], sm.IV)
	copy(result[len(sm.IV):], sm.Ciphertext)
	return result
}

// DeserializeSecureMessage deserializa uma mensagem segura de bytes
func DeserializeSecureMessage(data []byte) (*SecureMessage, error) {
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("dados muito pequenos para conter IV")
	}

	return &SecureMessage{
		IV:         data[:aes.BlockSize],
		Ciphertext: data[aes.BlockSize:],
	}, nil
}

// Errors
var (
	ErrInvalidPadding = fmt.Errorf("padding inválido")
	ErrInvalidKeySize = fmt.Errorf("tamanho de chave inválido")
)