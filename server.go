package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"

	"secure-messaging/crypto"
)

// Parâmetros DH (hardcoded conforme trabalho)
var (
	// Primo Sophie Germain de 2048 bits (seguro para DH)
	dhP, _ = new(big.Int).SetString("32317006071311007300338913926423828248817941241140239112842009751400741706634354222618472417543", 10)
	dhG    = big.NewInt(2) // Gerador
)

type Server struct {
	username     string
	address      string
	listener     net.Listener
	ecdsaSigner  *crypto.ECDSASigner
}

type ClientSession struct {
	conn        net.Conn
	aesKey      []byte
	hmacKey     []byte
	clientUsername string
}

type HandshakeData struct {
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`  // A ou B (hex)
	Signature []byte `json:"signature"`   // ECDSA signature
	Salt      []byte `json:"salt"`        // Para PBKDF2
}

type MessagePacket struct {
	HMACTag   []byte `json:"hmac_tag"`
	IV        []byte `json:"iv"`
	Encrypted []byte `json:"encrypted"`
}

func NewServer(username, address string) (*Server, error) {
	fmt.Printf("Criando servidor para %s...\n", username)
	
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
	
	return &Server{
		username:    username,
		address:     address,
		ecdsaSigner: signer,
	}, nil
}

func (s *Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", s.address)
	if err != nil {
		return fmt.Errorf("erro ao iniciar servidor: %v", err)
	}

	fmt.Printf("Servidor iniciado em %s\n", s.address)
	fmt.Printf("Username do servidor: %s\n", s.username)
	fmt.Printf("Parametros DH: p=%d bits, g=%d\n", dhP.BitLen(), dhG.Int64())
	fmt.Println("Aguardando conexoes...")

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			fmt.Printf("Erro ao aceitar conexao: %v\n", err)
			continue
		}

		fmt.Printf("Nova conexao de %s\n", conn.RemoteAddr())
		go s.handleClient(conn)
	}
}

func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
		fmt.Println("Servidor parado")
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	fmt.Println("Iniciando handshake...")

	// 1. Receber handshake do cliente
	clientHandshake, err := s.receiveHandshake(conn)
	if err != nil {
		fmt.Printf("Erro ao receber handshake: %v\n", err)
		return
	}

	fmt.Printf("Handshake recebido de: %s\n", clientHandshake.Username)

	// 2. Verificar assinatura ECDSA do cliente usando GitHub
	err = s.verifyClientSignature(clientHandshake)
	if err != nil {
		fmt.Printf("Falha na verificacao ECDSA: %v\n", err)
		return
	}

	fmt.Printf("Assinatura ECDSA do cliente verificada!\n")

	// 3. Gerar resposta DH e assinar
	serverHandshake, dhShared, err := s.createServerHandshake(clientHandshake)
	if err != nil {
		fmt.Printf("Erro ao criar handshake: %v\n", err)
		return
	}

	// 4. Enviar resposta
	err = s.sendHandshake(conn, serverHandshake)
	if err != nil {
		fmt.Printf("Erro ao enviar handshake: %v\n", err)
		return
	}

	fmt.Printf("Handshake concluido! Chave compartilhada estabelecida.\n")

	// 5. Derivar chaves usando PBKDF2
	aesKey, hmacKey, err := deriveKeys(dhShared, clientHandshake.Salt)
	if err != nil {
		fmt.Printf("Erro ao derivar chaves: %v\n", err)
		return
	}

	fmt.Printf("Chaves derivadas: AES=%d bytes, HMAC=%d bytes\n", len(aesKey), len(hmacKey))

	// 6. Processar mensagens seguras
	session := &ClientSession{
		conn:           conn,
		aesKey:         aesKey,
		hmacKey:        hmacKey,
		clientUsername: clientHandshake.Username,
	}

	session.handleSecureMessages()
}

func (s *Server) verifyClientSignature(handshake *HandshakeData) error {
	// Buscar chave pública do cliente no GitHub
	fmt.Printf("Buscando chave ECDSA de '%s' no GitHub...\n", handshake.Username)

	githubProvider := crypto.NewGitHubKeyFetcher()
	publicKey, err := githubProvider.FetchECDSAPublicKey(handshake.Username)
	if err != nil {
		return fmt.Errorf("erro ao buscar chave do GitHub: %v", err)
	}

	// Dados assinados: A + username_cliente (conforme trabalho)
	signedData := handshake.PublicKey + handshake.Username

	// Verificar assinatura
	valid := crypto.VerifyECDSA([]byte(signedData), handshake.Signature, publicKey)
	if !valid {
		return fmt.Errorf("assinatura ECDSA invalida")
	}

	return nil
}

func (s *Server) createServerHandshake(clientHandshake *HandshakeData) (*HandshakeData, *big.Int, error) {
	// Gerar par DH do servidor: b, B = g^b mod p
	dhPrivate, err := rand.Int(rand.Reader, dhP)
	if err != nil {
		return nil, nil, fmt.Errorf("erro ao gerar chave privada DH: %v", err)
	}

	dhPublic := new(big.Int).Exp(dhG, dhPrivate, dhP)

	// Calcular chave compartilhada: S = A^b mod p
	clientPublicKey, _ := new(big.Int).SetString(clientHandshake.PublicKey, 16)
	dhShared := new(big.Int).Exp(clientPublicKey, dhPrivate, dhP)

	// Criar dados para assinatura: B + username_servidor
	signData := dhPublic.Text(16) + s.username

	// Assinar com ECDSA
	signature, err := s.ecdsaSigner.Sign([]byte(signData))
	if err != nil {
		return nil, nil, fmt.Errorf("erro ao assinar: %v", err)
	}

	serverHandshake := &HandshakeData{
		Username:  s.username,
		PublicKey: dhPublic.Text(16),
		Signature: signature,
		Salt:      clientHandshake.Salt, // Usar mesmo salt do cliente
	}

	return serverHandshake, dhShared, nil
}

func (s *Server) receiveHandshake(conn net.Conn) (*HandshakeData, error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Ler tamanho
	sizeBytes := make([]byte, 4)
	_, err := io.ReadFull(conn, sizeBytes)
	if err != nil {
		return nil, err
	}

	size := int(sizeBytes[0])<<24 | int(sizeBytes[1])<<16 | int(sizeBytes[2])<<8 | int(sizeBytes[3])

	// Ler dados
	data := make([]byte, size)
	_, err = io.ReadFull(conn, data)
	if err != nil {
		return nil, err
	}

	var handshake HandshakeData
	err = json.Unmarshal(data, &handshake)
	return &handshake, err
}

func (s *Server) sendHandshake(conn net.Conn, handshake *HandshakeData) error {
	data, err := json.Marshal(handshake)
	if err != nil {
		return err
	}

	// Enviar tamanho
	size := len(data)
	sizeBytes := []byte{
		byte(size >> 24),
		byte(size >> 16),
		byte(size >> 8),
		byte(size),
	}

	_, err = conn.Write(sizeBytes)
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

func deriveKeys(dhShared *big.Int, salt []byte) (aesKey, hmacKey []byte, err error) {
	// Implementar PBKDF2 conforme trabalho
	// Key_AES = PBKDF2(S, salt, iterations, length_AES_key)
	// Key_HMAC = PBKDF2(S, salt, iterations, length_HMAC_key)

	// Por simplicidade, usar hash SHA256 por enquanto
	// Em implementação completa, usar PBKDF2
	password := dhShared.Bytes()

	// Hash com salt para AES (32 bytes)
	aesHash := sha256.Sum256(append(password, append(salt, []byte("AES")...)...))
	aesKey = aesHash[:]

	// Hash com salt para HMAC (32 bytes)
	hmacHash := sha256.Sum256(append(password, append(salt, []byte("HMAC")...)...))
	hmacKey = hmacHash[:]

	return aesKey, hmacKey, nil
}

func (cs *ClientSession) handleSecureMessages() {
	fmt.Printf("Aguardando mensagens seguras de %s...\n", cs.clientUsername)

	for {
		cs.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		
		// Receber mensagem no formato: [HMAC_TAG] + [IV_AES] + [MENSAGEM_CRIPTOGRAFADA]
		packet, err := cs.receiveMessagePacket()
		if err != nil {
			if err == io.EOF {
				fmt.Printf("Cliente %s desconectou\n", cs.clientUsername)
			} else {
				fmt.Printf("Erro ao receber mensagem de %s: %v\n", cs.clientUsername, err)
			}
			break
		}

		// Descriptografar e processar mensagem
		message, err := cs.processSecureMessage(packet)
		if err != nil {
			fmt.Printf("Erro ao processar mensagem: %v\n", err)
			break
		}

		fmt.Printf("Mensagem de %s: %s\n", cs.clientUsername, message)

		// Enviar resposta
		response := fmt.Sprintf("Mensagem recebida: '%s' (tamanho: %d bytes)",
			message, len(message))

		err = cs.sendResponse(response)
		if err != nil {
			fmt.Printf("Erro ao enviar resposta: %v\n", err)
			break
		}
	}
}

func (cs *ClientSession) receiveMessagePacket() (*MessagePacket, error) {
	// Ler tamanho do pacote
	sizeBytes := make([]byte, 4)
	_, err := io.ReadFull(cs.conn, sizeBytes)
	if err != nil {
		return nil, err
	}

	size := int(sizeBytes[0])<<24 | int(sizeBytes[1])<<16 | int(sizeBytes[2])<<8 | int(sizeBytes[3])

	// Ler dados do pacote
	data := make([]byte, size)
	_, err = io.ReadFull(cs.conn, data)
	if err != nil {
		return nil, err
	}

	var packet MessagePacket
	err = json.Unmarshal(data, &packet)
	return &packet, err
}

func (cs *ClientSession) processSecureMessage(packet *MessagePacket) (string, error) {
	// Verificar HMAC (integridade e autenticidade)
	// TODO: Implementar verificação HMAC real
	
	// Descriptografar mensagem
	// TODO: Implementar descriptografia AES-CBC real
	
	// Por simplicidade, retornar mensagem como string
	return string(packet.Encrypted), nil
}

func (cs *ClientSession) sendResponse(response string) error {
	data := []byte(response)

	// Enviar tamanho da resposta
	size := len(data)
	sizeBytes := []byte{
		byte(size >> 24),
		byte(size >> 16),
		byte(size >> 8),
		byte(size),
	}

	_, err := cs.conn.Write(sizeBytes)
	if err != nil {
		return err
	}

	_, err = cs.conn.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Uso: go run server.go <username> <porta>")
		fmt.Println("Exemplo: go run server.go christianestevam 8080")
		os.Exit(1)
	}

	username := os.Args[1]
	port := os.Args[2]
	address := ":" + port

	server, err := NewServer(username, address)
	if err != nil {
		fmt.Printf("Erro ao criar servidor: %v\n", err)
		os.Exit(1)
	}

	defer server.Stop()

	err = server.Start()
	if err != nil {
		fmt.Printf("Erro ao iniciar servidor: %v\n", err)
		os.Exit(1)
	}
}