package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"os"
	"strings"

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

func EncryptMedia(file *multipart.FileHeader, aes dto.EncryptRequest, user_id uuid.UUID, storagePath string) (string, error) {
	fileData, err := file.Open()
	if err != nil {
		return "", err
	}

	defer fileData.Close()

	// Read the file content
	fileContent, err := ioutil.ReadAll(fileData)
	if err != nil {
		return "", err
	}

	// Create the directory for the user if it doesn't exist
	userDirectory := storagePath + "/" + user_id.String()
	if _, err := os.Stat(userDirectory); os.IsNotExist(err) {
		if err := os.MkdirAll(userDirectory, os.ModePerm); err != nil {
			return "", err
		}
	}

	// Construct the filename and full filepath
	filename := userDirectory + "/" + file.Filename

	outputFile, err := os.Create(filename)
	if err != nil {
		return "", err
	}

	defer outputFile.Close()

	// Encrypt the file content using AES
	encryptedContent, err := GetAESEncrypted(string(fileContent), []byte(aes.Key), []byte(aes.IV))
	if err != nil {
		return "", err
	}

	// write it to the output file
	_, err = outputFile.WriteString(encryptedContent)
	if err != nil {
		return "", err
	}
	filename = LOCALHOST + filename

	return filename, nil
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

// PKCS5UnPadding  pads a certain blob of data with necessary data to be used in AES block cipher
func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	return src[:(length - unpadding)]
}

func DecryptFile(filename string, aes dto.EncryptRequest) (string, error) {
	inputFile, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer inputFile.Close()

	// Read the file content
	fileContent, err := ioutil.ReadAll(inputFile)
	if err != nil {
		return "", err
	}

	decryptedData, err := GetAESDecrypted(string(fileContent), []byte(aes.Key), []byte(aes.IV))
	if err != nil {
		return "", err
	}

	return string(decryptedData), nil
}
