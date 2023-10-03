package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"mime/multipart"
	"os"
	"strings"
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

func GenerateAESKey() []byte {
	key := make([]byte, 16) // 16 bytes for AES-128
	_, err := rand.Read(key)
	if err != nil {
		return nil
	}
	return key
}

func EncryptMedia(file *multipart.FileHeader, key []byte, storagePath string) (string, error) {
	fileData, err := file.Open()
	if err != nil {
		return "", err
	}

	defer fileData.Close()

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	filename := storagePath + "/" + file.Filename + ".enc"
	filepath := LOCALHOST + storagePath + "/" + file.Filename + ".enc"
	outputFile, err := os.Create(filename)
	if err != nil {
		return "", err
	}

	defer outputFile.Close()

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Write IV to the beginning of the output file
	_, err = outputFile.Write(iv)
	if err != nil {
		return "", err
	}

	// Create a stream cipher
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt the file and write it to the output file
	writer := &cipher.StreamWriter{S: stream, W: outputFile}
	if _, err := io.Copy(writer, fileData); err != nil {
		return "", err
	}

	return filepath, nil
}

func DecryptFile(filename string, key []byte) ([]byte, error) {
	inputFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer inputFile.Close()

	// Read the IV from the beginning of the file
	iv := make([]byte, aes.BlockSize)
	_, err = inputFile.Read(iv)
	if err != nil {
		return nil, err
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a stream cipher
	stream := cipher.NewCFBDecrypter(block, iv)

	// Create a buffer to store the decrypted data
	var decryptedData bytes.Buffer

	// Decrypt the file and store it in the buffer
	reader := &cipher.StreamReader{S: stream, R: inputFile}
	if _, err := io.Copy(&decryptedData, reader); err != nil {
		return nil, err
	}

	return decryptedData.Bytes(), nil
}
