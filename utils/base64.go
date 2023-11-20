package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Caknoooo/golang-clean_template/dto"
	"github.com/google/uuid"
)

const LOCALHOST = "http://localhost:8888/api/user/get/"

func ToBase64(b []byte) (string, error) {
	encodeBytes := base64.StdEncoding.EncodeToString(b)
	if encodeBytes == "" {
		return "", errors.New("encodeBytes is empty")
	}

	return encodeBytes, nil
}

func GetImage(path string, filename string) (string, error) {
	file, err := os.Open(path + "/" + filename)
	if err != nil {
		return "", err
	}

	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	base64, err := ToBase64(bytes)
	if err != nil {
		return "", err
	}

	return base64, nil
}

func GenerateFilename(path string, filename string) string {
	return path + "/" + filename
}

func GetExtension(file *multipart.FileHeader) string {
	return file.Filename[strings.LastIndex(file.Filename, ".")+1:]
}

func GenerateBytes(size int) string {

	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return "null"
	}
	return hex.EncodeToString(key)
}

func GetAESEncrypted(plaintext string, key []byte, iv []byte) (string, error) {
	var plainTextBlock []byte
	length := len(plaintext)

	if length%16 != 0 {
		extendBlock := 16 - (length % 16)
		plainTextBlock = make([]byte, length+extendBlock)
		copy(plainTextBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		plainTextBlock = make([]byte, length)
	}

	copy(plainTextBlock, plaintext)
	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainTextBlock))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, plainTextBlock)

	str := base64.StdEncoding.EncodeToString(ciphertext)

	return str, nil
}

// GetAESDecrypted decrypts given text in AES 256 CBC
func GetAESDecrypted(encrypted string, key []byte, iv []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("block size cant be zero")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)
	return ciphertext, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	return src[:(length - unpadding)]
}

func GetDESEncrypted(plaintext string, key []byte, iv []byte) (string, error) {
	block, err := des.NewCipher(key[:8])
	if err != nil {
		return "", err
	}

	// Padding the plaintext
	plaintext = string(PKCS5Padding([]byte(plaintext), des.BlockSize))

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv[:8]) // Use the first 8 bytes of IV
	mode.CryptBlocks(ciphertext, []byte(plaintext))

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func GetDESDecrypted(encrypted string, key []byte, iv []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := des.NewCipher(key[:8])
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("block size cannot be zero")
	}

	mode := cipher.NewCBCDecrypter(block, iv[:8])
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpadding the plaintext
	plaintext := PKCS5UnPadding(ciphertext)

	return plaintext, nil
}

func EncryptMedia(file *multipart.FileHeader, encryptionNeeds dto.EncryptRequest, user_id uuid.UUID, storagePath string, method string, typ string) (string, string, error) {
	fileData, err := file.Open()
	if err != nil {
		return "", "", err
	}

	defer fileData.Close()

	// Read the file content
	fileContent, err := ioutil.ReadAll(fileData)
	if err != nil {
		return "", "", err
	}

	var userDirectory string
	var filename string
	if typ == "register" {
		userDirectory = storagePath + "/KTP/"
		filename = userDirectory + user_id.String() + filepath.Ext(file.Filename)
	} else {
		userDirectory = storagePath + "/" + user_id.String()
		filename = userDirectory + "/" + file.Filename
	}

	if _, err := os.Stat(userDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(userDirectory, os.ModePerm); err != nil {
			return "", "", err
		}
	}

	outputFile, err := os.Create(filename)
	if err != nil {
		return "", "", err
	}
	defer outputFile.Close()

	start := time.Now()

	var encryptedContent string
	switch method {
	case "AES":
		encryptedContent, err = GetAESEncrypted(string(fileContent), []byte(encryptionNeeds.SymmetricKey), []byte(encryptionNeeds.IV))
		if err != nil {
			return "", "", err
		}

	case "DES":
		encryptedContent, err = GetDESEncrypted(string(fileContent), []byte(encryptionNeeds.SymmetricKey), []byte(encryptionNeeds.IV))
		if err != nil {
			return "", "", err
		}

	case "RC4":
		encryptedContent, err = EncryptRC4(string(fileContent), []byte(encryptionNeeds.SymmetricKey))
	default:
		return "", "", fmt.Errorf("unsupported ecryption method : %s", method)
	}

	elapsed := time.Since(start)
	elapsedSeconds := float64(elapsed.Microseconds()) / 1000000.0 // 1 million microseconds = 1 second
	TotalTime := fmt.Sprintf("Total time for encrypt is: %.10f seconds using ", elapsedSeconds)
	TotalTime = TotalTime + method

	_, err = outputFile.WriteString(encryptedContent)
	if err != nil {
		return "", "", err
	}

	filename = LOCALHOST + filename
	if typ != "register" {
		filename = filename + "/" + method
	}

	return filename, TotalTime, nil
}

func DecryptData(filename string, DecryptNeeds dto.EncryptRequest, method string) ([]byte, string, error) {
	inputFile, err := os.Open(filename)
	if err != nil {
		return nil, "", err
	}
	defer inputFile.Close()

	fileContent, err := ioutil.ReadAll(inputFile)
	if err != nil {
		return nil, "", err
	}

	start := time.Now()
	var decryptedData []byte

	switch method {
	case "AES":
		decryptedData, err = GetAESDecrypted(string(fileContent), []byte(DecryptNeeds.SymmetricKey), []byte(DecryptNeeds.IV))
		if err != nil {
			return nil, "", err
		}
	case "DES":
		decryptedData, err = GetDESDecrypted(string(fileContent), []byte(DecryptNeeds.SymmetricKey), []byte(DecryptNeeds.IV))
		if err != nil {
			return nil, "", err
		}
	case "RC4":
		decryptedData, err = DecryptRC4(string(fileContent), []byte(DecryptNeeds.SymmetricKey))
	default:
		return nil, "", fmt.Errorf("unsupported Decryption method: %s", method)
	}

	elapsed := time.Since(start)
	elapsedSeconds := float64(elapsed.Microseconds()) / 1000000.0 // 1 million microseconds = 1 second
	TotalTime := fmt.Sprintf("Total time for encrypt is: %.10f seconds using ", elapsedSeconds)
	TotalTime = TotalTime + method

	return decryptedData, TotalTime, nil
}

func EncryptRC4(plaintext string, key []byte) (string, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintextBytes := []byte(plaintext)
	ciphertext := make([]byte, len(plaintextBytes))
	cipher.XORKeyStream(ciphertext, plaintextBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptRC4(encodedString string, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		return []byte(""), fmt.Errorf("base64 decoding error: %v", err)
	}

	plaintext := make([]byte, len(ciphertextBytes))
	cipher.XORKeyStream(plaintext, ciphertextBytes)

	return plaintext, nil
}

func GenerateRSAKeyPair(bits int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}
	publicKey := &privateKey.PublicKey
	
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(privBlock)), base64.StdEncoding.EncodeToString(pem.EncodeToMemory(pubBlock)), nil
}

// Function to convert base64-encoded RSA private key string to *rsa.PrivateKey
func stringToPrivateKey(keyStr string) (*rsa.PrivateKey, error) {
	// Decode base64
	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}

	// Decode PEM
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func stringToPublicKey(keyStr string) (*rsa.PublicKey, error) {

	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, err
	}

	// Decode PEM
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	// Parse the public key
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Type assert to *rsa.PublicKey
	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to convert public key to RSA format")
	}

	return publicKey, nil
}

func encryptRCA(message []byte, publicKeyStr string) ([]byte, error) {
	publicKey, _ := stringToPublicKey(publicKeyStr)
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func decryptRCA(encrypted []byte, privateKeyStr string) ([]byte, error) {
	privateKey, _ := stringToPrivateKey(privateKeyStr)
	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, encrypted)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
