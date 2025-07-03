package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// KeyLoader carrega chaves ECDSA de arquivos
type KeyLoader struct {
	privateKeyPath string
	publicKeyPath  string
}

// NewKeyLoader cria um novo carregador de chaves
func NewKeyLoader(privateKeyPath, publicKeyPath string) *KeyLoader {
	return &KeyLoader{
		privateKeyPath: privateKeyPath,
		publicKeyPath:  publicKeyPath,
	}
}

// LoadECDSAKeyPair carrega par de chaves ECDSA de arquivos
func (kl *KeyLoader) LoadECDSAKeyPair() (*ECDSAKeyPair, error) {
	// Carregar chave privada
	privateKey, err := kl.loadPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("erro ao carregar chave privada: %v", err)
	}

	// A chave pública vem da privada
	publicKey := &privateKey.PublicKey

	return &ECDSAKeyPair{
		Private: privateKey,
		Public:  publicKey,
	}, nil
}

// loadPrivateKey carrega chave privada ECDSA de arquivo PEM
func (kl *KeyLoader) loadPrivateKey() (*ecdsa.PrivateKey, error) {
	// Verificar se arquivo existe
	if _, err := os.Stat(kl.privateKeyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("arquivo de chave privada não encontrado: %s", kl.privateKeyPath)
	}

	// Ler arquivo
	keyData, err := ioutil.ReadFile(kl.privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler arquivo de chave: %v", err)
	}

	// Detectar formato e parsear
	if isPEMFormat(keyData) {
		return kl.parsePEMPrivateKey(keyData)
	} else {
		return kl.parseOpenSSHPrivateKey(keyData)
	}
}

// isPEMFormat verifica se os dados estão em formato PEM
func isPEMFormat(data []byte) bool {
	return len(data) > 0 && data[0] == '-' // Começa com "-----"
}

// parsePEMPrivateKey parseia chave privada em formato PEM
func (kl *KeyLoader) parsePEMPrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("falha ao decodificar PEM")
	}

	// Tentar diferentes formatos
	if block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("chave não é ECDSA")
		}
		return ecdsaKey, nil
	}

	return nil, fmt.Errorf("tipo PEM não suportado: %s", block.Type)
}

// parseOpenSSHPrivateKey parseia chave privada em formato OpenSSH
func (kl *KeyLoader) parseOpenSSHPrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	// Para simplicidade, vamos usar a implementação básica
	// Em produção, usaria golang.org/x/crypto/ssh para parsing completo
	return nil, fmt.Errorf("formato OpenSSH não implementado - converta para PEM: ssh-keygen -p -m PEM -f %s", kl.privateKeyPath)
}

// ProtocolHandlerWithFixedKeys cria handler com chaves fixas
type ProtocolHandlerWithFixedKeys struct {
	*ProtocolHandler
	keyLoader *KeyLoader
}

// NewProtocolHandlerWithFixedKeys cria handler com chaves de arquivo
func NewProtocolHandlerWithFixedKeys(username, privateKeyPath string) (*ProtocolHandlerWithFixedKeys, error) {
	// Criar handler base
	handler, err := NewProtocolHandler(username)
	if err != nil {
		return nil, err
	}

	// Criar key loader
	keyLoader := NewKeyLoader(privateKeyPath, "")

	// Carregar chaves fixas
	keyPair, err := keyLoader.LoadECDSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("erro ao carregar chaves ECDSA: %v", err)
	}

	// Substituir as chaves geradas aleatoriamente pelas fixas
	handler.ecdsaKeyPair = keyPair

	fmt.Printf("✅ Chaves ECDSA carregadas de: %s\n", privateKeyPath)

	return &ProtocolHandlerWithFixedKeys{
		ProtocolHandler: handler,
		keyLoader:       keyLoader,
	}, nil
}

// GetDefaultKeyPaths retorna caminhos padrão para chaves SSH
func GetDefaultKeyPaths(username string) (string, string) {
	homeDir, _ := os.UserHomeDir()
	
	// Tentar diferentes nomes de arquivo comuns
	possibleKeys := []string{
		"github_ecdsa",
		"id_ecdsa", 
		"ecdsa_key",
		username + "_ecdsa",
	}

	for _, keyName := range possibleKeys {
		privateKeyPath := filepath.Join(homeDir, ".ssh", keyName)
		publicKeyPath := privateKeyPath + ".pub"
		
		if _, err := os.Stat(privateKeyPath); err == nil {
			return privateKeyPath, publicKeyPath
		}
	}

	// Default fallback
	privateKeyPath := filepath.Join(homeDir, ".ssh", "github_ecdsa")
	publicKeyPath := privateKeyPath + ".pub"
	
	return privateKeyPath, publicKeyPath
}

// AutoDetectKeyPaths detecta automaticamente chaves ECDSA
func AutoDetectKeyPaths() (string, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	
	// Procurar por arquivos de chave ECDSA
	files, err := ioutil.ReadDir(sshDir)
	if err != nil {
		return "", "", fmt.Errorf("erro ao ler diretório SSH: %v", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		
		// Pular arquivos .pub
		if filepath.Ext(name) == ".pub" {
			continue
		}

		// Verificar se é uma chave ECDSA
		fullPath := filepath.Join(sshDir, name)
		if isECDSAKeyFile(fullPath) {
			publicKeyPath := fullPath + ".pub"
			if _, err := os.Stat(publicKeyPath); err == nil {
				return fullPath, publicKeyPath, nil
			}
		}
	}

	return "", "", fmt.Errorf("nenhuma chave ECDSA encontrada em %s", sshDir)
}

// isECDSAKeyFile verifica se um arquivo contém uma chave ECDSA
func isECDSAKeyFile(filePath string) bool {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false
	}

	// Verificar se contém indicadores de chave ECDSA
	content := string(data)
	return contains(content, "ecdsa") || contains(content, "EC PRIVATE KEY") || 
		   (contains(content, "OPENSSH PRIVATE KEY") && len(data) < 2000) // ECDSA keys são menores
}

// contains verifica se string contém substring (case insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || len(s) > len(substr) && 
		    (hasSubstring(s, substr) || hasSubstring(strings.ToLower(s), strings.ToLower(substr))))
}

func hasSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}