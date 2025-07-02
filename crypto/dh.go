package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Parâmetros DH padrão seguros (RFC 3526 - 2048-bit MODP Group)
var (
	// Primo de 2048 bits do RFC 3526
	DefaultP, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	
	// Gerador
	DefaultG = big.NewInt(2)
)

// DHKeyPair representa um par de chaves Diffie-Hellman
type DHKeyPair struct {
	Private *big.Int
	Public  *big.Int
	P       *big.Int // Primo
	G       *big.Int // Gerador
}

// DHParams representa os parâmetros DH públicos
type DHParams struct {
	P *big.Int // Primo
	G *big.Int // Gerador
}

// GetDefaultDHParams retorna os parâmetros DH padrão seguros
func GetDefaultDHParams() *DHParams {
	return &DHParams{
		P: new(big.Int).Set(DefaultP),
		G: new(big.Int).Set(DefaultG),
	}
}

// GenerateDHKeyPair gera um novo par de chaves DH
func GenerateDHKeyPair(params *DHParams) (*DHKeyPair, error) {
	if params == nil {
		params = GetDefaultDHParams()
	}

	// Validar parâmetros
	if params.P == nil || params.G == nil {
		return nil, fmt.Errorf("parâmetros DH inválidos")
	}

	// Gerar chave privada aleatória: 1 < private < p-1
	max := new(big.Int).Sub(params.P, big.NewInt(2))
	private, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar chave privada DH: %v", err)
	}
	
	// Garantir que a chave privada seja >= 2
	private.Add(private, big.NewInt(2))
	
	// Calcular chave pública: g^private mod p
	public := new(big.Int).Exp(params.G, private, params.P)
	
	return &DHKeyPair{
		Private: private,
		Public:  public,
		P:       new(big.Int).Set(params.P),
		G:       new(big.Int).Set(params.G),
	}, nil
}

// ComputeSharedSecret computa o segredo compartilhado
func ComputeSharedSecret(privateKey, publicKey, p *big.Int) *big.Int {
	if privateKey == nil || publicKey == nil || p == nil {
		return nil
	}
	
	// Validar se a chave pública está no range válido
	if publicKey.Cmp(big.NewInt(1)) <= 0 || publicKey.Cmp(p) >= 0 {
		return nil
	}
	
	// Calcular segredo compartilhado: publicKey^privateKey mod p
	return new(big.Int).Exp(publicKey, privateKey, p)
}

// ComputeSharedSecretFromKeyPair computa o segredo usando o par de chaves
func (kp *DHKeyPair) ComputeSharedSecret(otherPublicKey *big.Int) *big.Int {
	return ComputeSharedSecret(kp.Private, otherPublicKey, kp.P)
}

// Validate valida um par de chaves DH
func (kp *DHKeyPair) Validate() error {
	if kp.Private == nil || kp.Public == nil || kp.P == nil || kp.G == nil {
		return fmt.Errorf("par de chaves DH incompleto")
	}
	
	// Verificar se private está no range válido: 1 < private < p-1
	if kp.Private.Cmp(big.NewInt(1)) <= 0 || kp.Private.Cmp(kp.P) >= 0 {
		return fmt.Errorf("chave privada DH fora do range válido")
	}
	
	// Verificar se public está no range válido: 1 < public < p-1
	if kp.Public.Cmp(big.NewInt(1)) <= 0 || kp.Public.Cmp(kp.P) >= 0 {
		return fmt.Errorf("chave pública DH fora do range válido")
	}
	
	// Verificar se public = g^private mod p
	expectedPublic := new(big.Int).Exp(kp.G, kp.Private, kp.P)
	if kp.Public.Cmp(expectedPublic) != 0 {
		return fmt.Errorf("chave pública DH não corresponde à chave privada")
	}
	
	return nil
}

// GetParams retorna os parâmetros DH do par de chaves
func (kp *DHKeyPair) GetParams() *DHParams {
	return &DHParams{
		P: new(big.Int).Set(kp.P),
		G: new(big.Int).Set(kp.G),
	}
}

// DHExchange representa uma troca DH completa
type DHExchange struct {
	params    *DHParams
	keyPair   *DHKeyPair
	otherPublic *big.Int
	sharedSecret *big.Int
}

// NewDHExchange cria uma nova troca DH
func NewDHExchange(params *DHParams) (*DHExchange, error) {
	keyPair, err := GenerateDHKeyPair(params)
	if err != nil {
		return nil, err
	}
	
	return &DHExchange{
		params:  params,
		keyPair: keyPair,
	}, nil
}

// GetPublicKey retorna a chave pública para enviar ao outro lado
func (dh *DHExchange) GetPublicKey() *big.Int {
	return new(big.Int).Set(dh.keyPair.Public)
}

// SetOtherPublicKey define a chave pública recebida do outro lado
func (dh *DHExchange) SetOtherPublicKey(otherPublic *big.Int) error {
	// Validar a chave pública recebida
	if otherPublic.Cmp(big.NewInt(1)) <= 0 || otherPublic.Cmp(dh.params.P) >= 0 {
		return fmt.Errorf("chave pública DH recebida é inválida")
	}
	
	dh.otherPublic = new(big.Int).Set(otherPublic)
	
	// Calcular o segredo compartilhado
	dh.sharedSecret = dh.keyPair.ComputeSharedSecret(dh.otherPublic)
	
	return nil
}

// GetSharedSecret retorna o segredo compartilhado (após SetOtherPublicKey)
func (dh *DHExchange) GetSharedSecret() *big.Int {
	if dh.sharedSecret == nil {
		return nil
	}
	return new(big.Int).Set(dh.sharedSecret)
}

// IsComplete retorna true se a troca DH está completa
func (dh *DHExchange) IsComplete() bool {
	return dh.sharedSecret != nil
}

// GetKeyPair retorna o par de chaves DH
func (dh *DHExchange) GetKeyPair() *DHKeyPair {
	return dh.keyPair
}