package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"os"
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

func GenerateBytes(size int) []byte {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil
	}
	return key
}

// GetAESEncrypted encrypts given text in AES 256 CBC
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

	block, err := aes.NewCipher([]byte(key))

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

func encryptDES(plainText string, key []byte) (string, error) {
	block, err := des.NewCipher([]byte(key[:8]))
	if err != nil {
		return "", err
	}

	paddedPlaintext := PKCS5Padding([]byte(plainText), block.BlockSize())

	ciphertext := make([]byte, len(paddedPlaintext))
	iv := make([]byte, des.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// Return the encrypted content as a hex-encoded string
	return hex.EncodeToString(ciphertext), nil
}

func decryptDES(ciphertextHex string, key string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	block, err := des.NewCipher([]byte(key[:8]))
	if err != nil {
		return "", err
	}

	iv := make([]byte, des.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove the padding
	plainText := string(PKCS5UnPadding(ciphertext))

	return plainText, nil
}

func EncryptMedia(file *multipart.FileHeader, aes dto.EncryptRequest, user_id uuid.UUID, storagePath string, method string) (string, string, error) {
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

	userDirectory := storagePath + "/" + user_id.String()
	if _, err := os.Stat(userDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(userDirectory, os.ModePerm); err != nil {
			return "", "", err
		}
	}

	filename := userDirectory + "/" + file.Filename 

	outputFile, err := os.Create(filename)
	if err != nil {
		return "", "", err
	}
	defer outputFile.Close()

	start := time.Now()

	var encryptedContent string

	switch method {
	case "AES":
		encryptedContent, err = GetAESEncrypted(string(fileContent), []byte(aes.Key), []byte(aes.IV))
		if err != nil {
			return "", "", err
		}

	case "DES":
		encryptedContent, err = encryptDES(string(fileContent), []byte(aes.Key))
		if err != nil {
			return "", "", err
		}

	case "RC4":
		//perform RC4
	default:
		return "", "", fmt.Errorf("unsupported ecryption method : %s", method)
	}

	elapsed := time.Since(start)
	elapsedSeconds := float64(elapsed.Microseconds()) / 1000000.0 // 1 million microseconds = 1 second
	TotalTime := fmt.Sprintf("Total time for encrypt is: %.6f seconds", elapsedSeconds)

	_, err = outputFile.WriteString(encryptedContent)
	if err != nil {
		return "", "", err
	}
	filename = LOCALHOST + filename + "/" + method

	return filename, TotalTime, nil
}

func DecryptData(filename string, aes dto.EncryptRequest, method string) (string, string, error) {
	inputFile, err := os.Open(filename)
	if err != nil {
		return "", "", err
	}
	defer inputFile.Close()

	// Read the file content
	fileContent, err := ioutil.ReadAll(inputFile)
	if err != nil {
		return "", "", err
	}

	start := time.Now()
	var decryptedData []byte
	switch method {
	case "AES":
		decryptedData, err = GetAESDecrypted(string(fileContent), []byte(aes.Key), []byte(aes.IV))
	if err != nil {
		return "", "", err
	}
	case "DES":
		//urDES decrypt here

	case "RC4":
		//ur RC4 logic here

	default:
		return "", "", fmt.Errorf("unsupported Decryption method: %s", method)
	}

	

	elapsed := time.Since(start)
	elapsedSeconds := float64(elapsed.Microseconds()) / 1000000.0 // 1 million microseconds = 1 second
	TotalTime := fmt.Sprintf("Total time for decrypt is: %.6f seconds", elapsedSeconds)

	return string(decryptedData), TotalTime, nil
}
