package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"os"
	"strings"
	"time"
	"path/filepath"

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

	mode := cipher.NewCBCDecrypter(block, iv[:8]) // Use the first 8 bytes of IV
	mode.CryptBlocks(ciphertext, ciphertext)

	// Unpadding the plaintext
	plaintext := PKCS5UnPadding(ciphertext)

	return plaintext, nil
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
		encryptedContent, err = GetDESEncrypted(string(fileContent), []byte(aes.Key), []byte(aes.IV))
		if err != nil {
			return "", "", err
		}

	case "RC4":
		encryptedContent, err = EncryptRC4(string(fileContent), []byte(aes.Key))
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

func DecryptData(filename string, aes dto.EncryptRequest, method string) ([]byte, string, error) {
	inputFile, err := os.Open(filename)
	if err != nil {
		return nil, "", err
	}
	defer inputFile.Close()

	// Read the file content
	fileContent, err := ioutil.ReadAll(inputFile)
	if err != nil {
		return nil, "", err
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
		decryptedData, err = GetDESDecrypted(string(fileContent), []byte(aes.Key), []byte(aes.IV))
		if err != nil {
			return nil, "", err
		}
	case "RC4":
		decryptedData, err = DecryptRC4(string(fileContent), []byte(aes.Key))

	default:
		return nil, "", fmt.Errorf("unsupported Decryption method: %s", method)
	}

	elapsed := time.Since(start)
	elapsedSeconds := float64(elapsed.Microseconds()) / 1000000.0 // 1 million microseconds = 1 second
	TotalTime := fmt.Sprintf("Total time for decrypt is: %.6f seconds", elapsedSeconds)

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

func UploadKTP(file *multipart.FileHeader, storage string, id uuid.UUID) (string, error){
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	// Create the storage directory if it doesn't exist
	storagePath := storage + "/KTP/"
 	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		err = os.Mkdir(storagePath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}

	KTPPath := storagePath + id.String() + filepath.Ext(file.Filename)
	dst, err := os.Create(KTPPath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return "", err
	}

	return KTPPath, nil
}


