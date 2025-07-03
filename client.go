package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"secure-messaging/crypto"
)

// Parâmetros DH (devem ser os mesmos do servidor)
var (
	dhP, _ = new(big.Int).SetString("32317006071311007300338913926423828248817941241140239112842009751400741706634354222618472417543", 10)
	dhG    = big.NewInt(2)
)

type Client struct {
	username    string
	serverAddr  string
	connection  net.Conn
	ecdsaSigner *crypto.ECDSASigner
	aesKey      []byte
	hmacKey     []byte
}

type HandshakeData struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
	Signature []byte `json:"signature"`
	Salt      []byte `json:"salt"`
}

type MessagePacket struct {
	HMACTag   []byte `json:"hmac_tag"`
	IV        []byte `json:"iv"`
	Encrypted []byte `json:"encrypted"`
}

func NewClient(username, serverAddr string) (*Client, error) {
	fmt.Printf("Criando cliente para %s...\n", username)
	
	// Buscar chave ECDSA do GitHub primeiro
	fmt.Printf("Buscando chave ECDSA de '%s' no GitHub...\n", username)
	githubProvider := crypto.NewGitHubKeyFetcher()
	publicKey, err := githubProvider.FetchECDSAPublicKey(username)
	if err != nil {
		return nil, fmt.Errorf("erro ao buscar chave ECDSA do GitHub: %v\nAdicione sua chave ECDSA em https://github.com/settings/keys", err)
	}
	
	fmt.Printf("Chave ECDSA encontrada no GitHub para '%s'\n", username)
	
	// Tentar carregar chave privada local correspondente
	var signer *crypto.ECDSASigner
	localProvider := crypto.NewLocalKeyProvider("keys")
	if privateKey, err := localProvider.LoadPrivateKey(username); err == nil {
		// Verificar se a chave local corresponde à do GitHub
		if privateKey.PublicKey.Equal(publicKey) {
			signer = crypto.NewECDSASignerFromPrivateKey(privateKey)
			fmt.Printf("Usando chave ECDSA local que corresponde ao GitHub\n")
		} else {
			return nil, fmt.Errorf("chave local não corresponde à chave do GitHub")
		}
	} else {
		return nil, fmt.Errorf("chave privada local não encontrada para %s: %v", username, err)
	}

	return &Client{
		username:    username,
		serverAddr:  serverAddr,
		ecdsaSigner: signer,
	}, nil
}

func (c *Client) Connect() error {
	var err error
	c.connection, err = net.Dial("tcp", c.serverAddr)
	if err != nil {
		return fmt.Errorf("erro ao conectar ao servidor: %v", err)
	}

	fmt.Printf("Conectado ao servidor %s\n", c.serverAddr)
	return nil
}

func (c *Client) Disconnect() {
	if c.connection != nil {
		c.connection.Close()
		fmt.Println("Desconectado do servidor")
	}
}

func (c *Client) performHandshake() error {
	fmt.Println("Iniciando handshake...")

	// Gerar salt para PBKDF2
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return fmt.Errorf("erro ao gerar salt: %v", err)
	}

	// 1. Gerar par DH: a, A = g^a mod p
	dhPrivate, err := rand.Int(rand.Reader, dhP)
	if err != nil {
		return fmt.Errorf("erro ao gerar chave privada DH: %v", err)
	}

	dhPublic := new(big.Int).Exp(dhG, dhPrivate, dhP)

	// 2. Assinar A + username_cliente com chave ECDSA
	signData := dhPublic.Text(16) + c.username
	signature, err := c.ecdsaSigner.Sign([]byte(signData))
	if err != nil {
		return fmt.Errorf("erro ao assinar dados: %v", err)
	}

	// 3. Criar mensagem de handshake
	clientHandshake := &HandshakeData{
		Username:  c.username,
		PublicKey: dhPublic.Text(16),
		Signature: signature,
		Salt:      salt,
	}

	// 4. Enviar handshake
	err = c.sendHandshake(clientHandshake)
	if err != nil {
		return fmt.Errorf("erro ao enviar handshake: %v", err)
	}

	// 5. Receber resposta do servidor
	serverHandshake, err := c.receiveHandshake()
	if err != nil {
		return fmt.Errorf("erro ao receber handshake do servidor: %v", err)
	}

	fmt.Printf("Servidor: %s\n", serverHandshake.Username)

	// 6. Verificar assinatura ECDSA do servidor
	err = c.verifyServerSignature(serverHandshake)
	if err != nil {
		return fmt.Errorf("falha na verificacao ECDSA do servidor: %v", err)
	}

	fmt.Printf("Assinatura ECDSA do servidor verificada!\n")

	// 7. Calcular chave compartilhada: S = B^a mod p
	serverPublicKey, _ := new(big.Int).SetString(serverHandshake.PublicKey, 16)
	dhShared := new(big.Int).Exp(serverPublicKey, dhPrivate, dhP)

	// 8. Derivar chaves usando PBKDF2
	c.aesKey, c.hmacKey, err = deriveKeys(dhShared, salt)
	if err != nil {
		return fmt.Errorf("erro ao derivar chaves: %v", err)
	}

	fmt.Printf("Handshake concluido com sucesso!\n")
	fmt.Printf("Sessao segura estabelecida.\n")
	return nil
}

func (c *Client) verifyServerSignature(handshake *HandshakeData) error {
	// Buscar chave pública do servidor no GitHub
	fmt.Printf("Buscando chave ECDSA de '%s' no GitHub...\n", handshake.Username)

	githubProvider := crypto.NewGitHubKeyFetcher()
	publicKey, err := githubProvider.FetchECDSAPublicKey(handshake.Username)
	if err != nil {
		return fmt.Errorf("erro ao buscar chave do GitHub: %v", err)
	}

	// Dados assinados: B + username_servidor (conforme trabalho)
	signedData := handshake.PublicKey + handshake.Username

	// Verificar assinatura
	valid := crypto.VerifyECDSA([]byte(signedData), handshake.Signature, publicKey)
	if !valid {
		return fmt.Errorf("assinatura ECDSA invalida")
	}

	return nil
}

func (c *Client) sendHandshake(handshake *HandshakeData) error {
	data, err := json.Marshal(handshake)
	if err != nil {
		return fmt.Errorf("erro ao serializar handshake: %v", err)
	}

	// Enviar tamanho da mensagem primeiro (4 bytes)
	size := len(data)
	sizeBytes := []byte{
		byte(size >> 24),
		byte(size >> 16),
		byte(size >> 8),
		byte(size),
	}

	_, err = c.connection.Write(sizeBytes)
	if err != nil {
		return fmt.Errorf("erro ao enviar tamanho do handshake: %v", err)
	}

	_, err = c.connection.Write(data)
	if err != nil {
		return fmt.Errorf("erro ao enviar dados do handshake: %v", err)
	}

	return nil
}

func (c *Client) receiveHandshake() (*HandshakeData, error) {
	c.connection.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Ler tamanho da mensagem (4 bytes)
	sizeBytes := make([]byte, 4)
	_, err := io.ReadFull(c.connection, sizeBytes)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler tamanho do handshake: %v", err)
	}

	size := int(sizeBytes[0])<<24 | int(sizeBytes[1])<<16 | int(sizeBytes[2])<<8 | int(sizeBytes[3])

	// Ler dados da mensagem
	data := make([]byte, size)
	_, err = io.ReadFull(c.connection, data)
	if err != nil {
		return nil, fmt.Errorf("erro ao ler dados do handshake: %v", err)
	}

	var msg HandshakeData
	err = json.Unmarshal(data, &msg)
	if err != nil {
		return nil, fmt.Errorf("erro ao deserializar handshake: %v", err)
	}

	return &msg, nil
}

func (c *Client) sendSecureMessage(message string) error {
	// Gerar IV aleatório para AES
	iv := make([]byte, 16) // AES block size
	_, err := rand.Read(iv)
	if err != nil {
		return fmt.Errorf("erro ao gerar IV: %v", err)
	}

	// Criptografar mensagem com AES-CBC
	// TODO: Implementar AES-CBC real
	encrypted := []byte(message) // Por simplicidade, por enquanto

	// Calcular HMAC de IV + MENSAGEM_CRIPTOGRAFADA
	// TODO: Implementar HMAC real
	hmacTag := make([]byte, 32) // Por simplicidade, por enquanto

	// Criar pacote de mensagem
	packet := &MessagePacket{
		HMACTag:   hmacTag,
		IV:        iv,
		Encrypted: encrypted,
	}

	// Serializar e enviar
	data, err := json.Marshal(packet)
	if err != nil {
		return fmt.Errorf("erro ao serializar mensagem: %v", err)
	}

	// Enviar tamanho da mensagem
	size := len(data)
	sizeBytes := []byte{
		byte(size >> 24),
		byte(size >> 16),
		byte(size >> 8),
		byte(size),
	}

	_, err = c.connection.Write(sizeBytes)
	if err != nil {
		return fmt.Errorf("erro ao enviar tamanho da mensagem: %v", err)
	}

	_, err = c.connection.Write(data)
	if err != nil {
		return fmt.Errorf("erro ao enviar mensagem: %v", err)
	}

	return nil
}

func (c *Client) receiveResponse() (string, error) {
	c.connection.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Ler tamanho da resposta
	sizeBytes := make([]byte, 4)
	_, err := io.ReadFull(c.connection, sizeBytes)
	if err != nil {
		return "", fmt.Errorf("erro ao ler tamanho da resposta: %v", err)
	}

	size := int(sizeBytes[0])<<24 | int(sizeBytes[1])<<16 | int(sizeBytes[2])<<8 | int(sizeBytes[3])

	// Ler dados da resposta
	data := make([]byte, size)
	_, err = io.ReadFull(c.connection, data)
	if err != nil {
		return "", fmt.Errorf("erro ao ler dados da resposta: %v", err)
	}

	return string(data), nil
}

func deriveKeys(dhShared *big.Int, salt []byte) (aesKey, hmacKey []byte, err error) {
	// Implementar PBKDF2 conforme trabalho
	// Por simplicidade, usar hash SHA256 por enquanto
	password := dhShared.Bytes()

	// Hash com salt para AES (32 bytes)
	aesHash := sha256.Sum256(append(password, append(salt, []byte("AES")...)...))
	aesKey = aesHash[:]

	// Hash com salt para HMAC (32 bytes)
	hmacHash := sha256.Sum256(append(password, append(salt, []byte("HMAC")...)...))
	hmacKey = hmacHash[:]

	return aesKey, hmacKey, nil
}

func (c *Client) Run() error {
	// Conectar ao servidor
	err := c.Connect()
	if err != nil {
		return err
	}
	defer c.Disconnect()

	// Realizar handshake
	err = c.performHandshake()
	if err != nil {
		return err
	}

	// Interface de usuário
	fmt.Println("\n=== Sistema de Mensagens Seguras ===")
	fmt.Println("Digite suas mensagens (ou 'quit' para sair):")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		message := strings.TrimSpace(scanner.Text())
		if message == "quit" {
			break
		}

		if message == "" {
			continue
		}

		// Enviar mensagem segura
		err = c.sendSecureMessage(message)
		if err != nil {
			fmt.Printf("Erro ao enviar mensagem: %v\n", err)
			continue
		}

		// Receber resposta
		response, err := c.receiveResponse()
		if err != nil {
			fmt.Printf("Erro ao receber resposta: %v\n", err)
			continue
		}

		fmt.Printf("Servidor: %s\n", response)
	}

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Uso: go run client.go <username> <servidor:porta> [opcoes]")
		fmt.Println("Opcoes:")
		fmt.Println("  --no-github     Desabilitar verificacao GitHub")
		fmt.Println("")
		fmt.Println("Exemplos:")
		fmt.Println("  go run client.go alice localhost:8080")
		fmt.Println("  go run client.go alice localhost:8080 --no-github")
		os.Exit(1)
	}

	username := os.Args[1]
	serverAddr := os.Args[2]

	client, err := NewClient(username, serverAddr)
	if err != nil {
		fmt.Printf("Erro ao criar cliente: %v\n", err)
		os.Exit(1)
	}

	err = client.Run()
	if err != nil {
		fmt.Printf("Erro na execucao do cliente: %v\n", err)
		os.Exit(1)
	}
}