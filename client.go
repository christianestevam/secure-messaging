package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"secure-messaging/crypto"
)

type Client struct {
	username        string
	serverAddr      string
	protocolHandler *crypto.ProtocolHandler
	connection      net.Conn
}

func NewClient(username, serverAddr string) (*Client, error) {
	handler, err := crypto.NewProtocolHandler(username)
	if err != nil {
		return nil, fmt.Errorf("erro ao criar handler do protocolo: %v", err)
	}

	return &Client{
		username:        username,
		serverAddr:      serverAddr,
		protocolHandler: handler,
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

	// 1. Criar mensagem de handshake
	handshakeMsg, err := c.protocolHandler.CreateHandshakeMessage()
	if err != nil {
		return fmt.Errorf("erro ao criar mensagem de handshake: %v", err)
	}

	// 2. Enviar nossa mensagem de handshake
	err = c.sendHandshakeMessage(handshakeMsg)
	if err != nil {
		return fmt.Errorf("erro ao enviar handshake: %v", err)
	}

	// 3. Receber mensagem de handshake do servidor
	serverHandshake, err := c.receiveHandshakeMessage()
	if err != nil {
		return fmt.Errorf("erro ao receber handshake do servidor: %v", err)
	}

	// 4. Processar handshake (sem verificação ECDSA para demonstração)
	fmt.Printf("Servidor: %s\n", serverHandshake.Username)
	fmt.Println("AVISO: Pulando verificação de chave ECDSA do GitHub para demonstração")
	
	err = c.processHandshakeWithoutECDSAVerification(serverHandshake)
	if err != nil {
		return fmt.Errorf("erro ao processar handshake: %v", err)
	}

	fmt.Println("Handshake concluído com sucesso!")
	fmt.Println("Sessão segura estabelecida.")
	return nil
}

// Versão insegura apenas para demonstração - NÃO USE EM PRODUÇÃO
func (c *Client) processHandshakeWithoutECDSAVerification(msg *crypto.HandshakeMessage) error {
	// Definir chave pública DH do servidor
	err := c.protocolHandler.SetOtherPublicKey(msg.PublicKey)
	if err != nil {
		return fmt.Errorf("erro ao processar chave pública DH: %v", err)
	}

	// Estabelecer sessão segura
	sharedSecret := c.protocolHandler.GetSharedSecret()
	session, err := crypto.NewSecureSession(sharedSecret, nil)
	if err != nil {
		return fmt.Errorf("erro ao estabelecer sessão segura: %v", err)
	}

	// Atualizar o handler com a sessão
	c.protocolHandler.SetSession(session)
	
	return nil
}

func (c *Client) sendHandshakeMessage(msg *crypto.HandshakeMessage) error {
	data, err := json.Marshal(msg)
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

func (c *Client) receiveHandshakeMessage() (*crypto.HandshakeMessage, error) {
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

	var msg crypto.HandshakeMessage
	err = json.Unmarshal(data, &msg)
	if err != nil {
		return nil, fmt.Errorf("erro ao deserializar handshake: %v", err)
	}

	return &msg, nil
}

func (c *Client) sendSecureMessage(message string) error {
	if !c.protocolHandler.IsSessionEstablished() {
		return fmt.Errorf("sessão segura não estabelecida")
	}

	// Criptografar mensagem
	secureMsg, err := c.protocolHandler.SendSecureMessage([]byte(message))
	if err != nil {
		return fmt.Errorf("erro ao criptografar mensagem: %v", err)
	}

	// Serializar mensagem
	data := secureMsg.Serialize()

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
	if len(os.Args) != 3 {
		fmt.Println("Uso: go run client.go <username> <servidor:porta>")
		fmt.Println("Exemplo: go run client.go alice localhost:8080")
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
		fmt.Printf("Erro na execução do cliente: %v\n", err)
		os.Exit(1)
	}
}