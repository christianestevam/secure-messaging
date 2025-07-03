package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// ECDSAKeyPair representa um par de chaves ECDSA
type ECDSAKeyPair struct {
	Private *ecdsa.PrivateKey
	Public  *ecdsa.PublicKey
}

// GenerateECDSAKeyPair gera um par de chaves ECDSA usando P-256
func GenerateECDSAKeyPair() (*ECDSAKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar chave ECDSA: %v", err)
	}

	return &ECDSAKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

// GenerateECDSAKeyPairWithCurve gera um par de chaves ECDSA com curva específica
func GenerateECDSAKeyPairWithCurve(curve elliptic.Curve) (*ECDSAKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar chave ECDSA: %v", err)
	}

	return &ECDSAKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

// SignECDSA assina dados com ECDSA usando SHA-256
func SignECDSA(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("chave privada é nil")
	}

	// Calcular hash SHA-256 dos dados
	hash := sha256.Sum256(data)

	// Assinar o hash
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("erro ao assinar dados: %v", err)
	}

	// Serializar a assinatura (r || s)
	signature := SerializeECDSASignature(r, s)
	return signature, nil
}

// VerifyECDSA verifica uma assinatura ECDSA
func VerifyECDSA(data, signature []byte, publicKey *ecdsa.PublicKey) bool {
	if publicKey == nil || len(signature) == 0 {
		return false
	}

	// Calcular hash SHA-256 dos dados
	hash := sha256.Sum256(data)

	// Deserializar a assinatura
	r, s, err := DeserializeECDSASignature(signature)
	if err != nil {
		return false
	}

	// Verificar a assinatura
	return ecdsa.Verify(publicKey, hash[:], r, s)
}

// SerializeECDSASignature serializa uma assinatura ECDSA (r, s) para bytes
func SerializeECDSASignature(r, s *big.Int) []byte {
	// Tamanho fixo de 32 bytes para cada componente (P-256)
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)

	// Copiar bytes de r e s, padding com zeros à esquerda se necessário
	rData := r.Bytes()
	sData := s.Bytes()

	copy(rBytes[32-len(rData):], rData)
	copy(sBytes[32-len(sData):], sData)

	// Concatenar r || s
	signature := make([]byte, 64)
	copy(signature[:32], rBytes)
	copy(signature[32:], sBytes)

	return signature
}

// DeserializeECDSASignature deserializa uma assinatura ECDSA de bytes
func DeserializeECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature) != 64 {
		return nil, nil, fmt.Errorf("assinatura deve ter 64 bytes, recebido: %d", len(signature))
	}

	// Extrair r e s
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return r, s, nil
}

// SerializeECDSAPublicKey serializa uma chave pública ECDSA para PEM
func SerializeECDSAPublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("chave pública é nil")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("erro ao serializar chave pública: %v", err)
	}

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	return pem.EncodeToMemory(publicKeyPEM), nil
}

// DeserializeECDSAPublicKey deserializa uma chave pública ECDSA de PEM
func DeserializeECDSAPublicKey(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("erro ao decodificar PEM")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("tipo PEM inválido: esperado 'PUBLIC KEY', recebido '%s'", block.Type)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("erro ao parsear chave pública: %v", err)
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("chave não é ECDSA")
	}

	return publicKey, nil
}

// SerializeECDSAPrivateKey serializa uma chave privada ECDSA para PEM
func SerializeECDSAPrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("chave privada é nil")
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("erro ao serializar chave privada: %v", err)
	}

	privateKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	return pem.EncodeToMemory(privateKeyPEM), nil
}

// DeserializeECDSAPrivateKey deserializa uma chave privada ECDSA de PEM
func DeserializeECDSAPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("erro ao decodificar PEM")
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("tipo PEM inválido: esperado 'EC PRIVATE KEY', recebido '%s'", block.Type)
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("erro ao parsear chave privada: %v", err)
	}

	return privateKey, nil
}

// ValidateECDSAPublicKey valida uma chave pública ECDSA
func ValidateECDSAPublicKey(publicKey *ecdsa.PublicKey) error {
	if publicKey == nil {
		return fmt.Errorf("chave pública é nil")
	}

	if publicKey.Curve == nil {
		return fmt.Errorf("curva da chave pública é nil")
	}

	// Verificar se o ponto está na curva
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return fmt.Errorf("chave pública não está na curva")
	}

	// Verificar se não é o ponto no infinito
	if publicKey.X.Sign() == 0 && publicKey.Y.Sign() == 0 {
		return fmt.Errorf("chave pública é o ponto no infinito")
	}

	return nil
}

// ECDSASigner representa um assinador ECDSA
type ECDSASigner struct {
	keyPair *ECDSAKeyPair
}

// NewECDSASigner cria um novo assinador ECDSA
func NewECDSASigner() (*ECDSASigner, error) {
	keyPair, err := GenerateECDSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("erro ao criar assinador ECDSA: %v", err)
	}

	return &ECDSASigner{
		keyPair: keyPair,
	}, nil
}

// NewECDSASignerFromPrivateKey cria um assinador ECDSA a partir de uma chave privada
func NewECDSASignerFromPrivateKey(privateKey *ecdsa.PrivateKey) *ECDSASigner {
	return &ECDSASigner{
		keyPair: &ECDSAKeyPair{
			Private: privateKey,
			Public:  &privateKey.PublicKey,
		},
	}
}

// Sign assina dados
func (signer *ECDSASigner) Sign(data []byte) ([]byte, error) {
	return SignECDSA(data, signer.keyPair.Private)
}

// GetPublicKey retorna a chave pública
func (signer *ECDSASigner) GetPublicKey() *ecdsa.PublicKey {
	return signer.keyPair.Public
}

// GetPrivateKey retorna a chave privada
func (signer *ECDSASigner) GetPrivateKey() *ecdsa.PrivateKey {
	return signer.keyPair.Private
}

// ECDSAVerifier representa um verificador ECDSA
type ECDSAVerifier struct {
	publicKey *ecdsa.PublicKey
}

// NewECDSAVerifier cria um novo verificador ECDSA
func NewECDSAVerifier(publicKey *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	if err := ValidateECDSAPublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("chave pública inválida: %v", err)
	}

	return &ECDSAVerifier{
		publicKey: publicKey,
	}, nil
}

// Verify verifica uma assinatura
func (verifier *ECDSAVerifier) Verify(data, signature []byte) bool {
	return VerifyECDSA(data, signature, verifier.publicKey)
}

// GetPublicKey retorna a chave pública
func (verifier *ECDSAVerifier) GetPublicKey() *ecdsa.PublicKey {
	return verifier.publicKey
}

// SignDataWithUsername assina dados concatenados com username
func SignDataWithUsername(data []byte, username string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Concatenar dados + username
	combined := append(data, []byte(username)...)
	return SignECDSA(combined, privateKey)
}

// VerifyDataWithUsername verifica assinatura de dados concatenados com username
func VerifyDataWithUsername(data []byte, username string, signature []byte, publicKey *ecdsa.PublicKey) bool {
	// Concatenar dados + username
	combined := append(data, []byte(username)...)
	return VerifyECDSA(combined, signature, publicKey)
}

// ===== NOVAS FUNÇÕES ADICIONADAS =====

// SHA256Hash calcula hash SHA256 (função utilitária para compatibilidade)
func SHA256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}