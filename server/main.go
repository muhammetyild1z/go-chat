package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/pbkdf2"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var clients = make(map[*websocket.Conn]bool)
var broadcast = make(chan Message)

type Message struct {
	UserName string `json:"username"`
	Message  string `json:"message"`
}

func main() {
	fs := http.FileServer(http.Dir("../client"))
	http.Handle("/", fs)
	http.HandleFunc("/ws", handleConnections)

	// Mesajları dinle
	go handleMessages()

	// Sunucu başlat
	fmt.Println("HTTP server started on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Server error:", err)
	}

}

const BlockSize = 32

var passphrase string

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Upgrade error:", err)
		return
	}
	defer ws.Close()
	passphrase, err = PassphraseGenerator(BlockSize)
	if err != nil {
		fmt.Println("not salt")
	}
	clients[ws] = true
	fmt.Println("Client connected")

	for {
		var msg Message
		err := ws.ReadJSON(&msg)
		if err != nil {
			fmt.Println("Read error:", err)
			delete(clients, ws)
			break
		}

		// Şifreleme
		key := deriveKey(passphrase, nil)
		encryptedMsg, _ := encrypt(key, msg.Message)
		msg.Message = encryptedMsg
		fmt.Println(msg.Message)
		broadcast <- msg
	}
}

func handleMessages() {
	for {
		msg := <-broadcast

		// Mesajı deşifre et
		key := deriveKey(passphrase, nil)
		decryptedMsg, _ := decrypt(key, msg.Message)
		msg.Message = decryptedMsg

		for client := range clients {
			err := client.WriteJSON(msg)

			if err != nil {
				fmt.Println("Write error:", err)
				client.Close()
				delete(clients, client)
			}

		}
	}
}

func deriveKey(passphrase string, salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, 8)
		//rnd salt
	}
	return pbkdf2.Key([]byte(passphrase), salt, 1000, BlockSize, sha256.New)

}
func PassphraseGenerator(blockSize int) (string, error) {
	if blockSize <= 0 {
		return "", fmt.Errorf("blocksize must be greater than 0")
	}

	bytes := make([]byte, blockSize)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func addBase64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)

	}
	return value
}

func removeBase64Padding(value string) string {
	return strings.Replace(value, "=", "", -1)
}

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func UnPad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, errors.New("unpad error")
	}
	return src[:length-unpadding], nil
}
func encrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	msg := Pad([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
	finalMsg := removeBase64Padding(base64.URLEncoding.EncodeToString(ciphertext))

	return finalMsg, nil
}

func decrypt(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.URLEncoding.DecodeString(addBase64Padding(text))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("blocksize must be multipe of decoded message length")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := UnPad(msg)
	if err != nil {
		return "", err
	}
	fmt.Println("Decrypted message:", string(unpadMsg))
	return string(unpadMsg), nil
}
