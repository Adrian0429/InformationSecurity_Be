package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"os"
	"regexp"
)

func hashString(input []byte) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hashSum := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashSum)
	return hashString
}

func hashFile(filePath string) (string, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Create a new SHA-256 hash object
	hasher := sha256.New()

	// Copy the file content to the hash object
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	// Get the final hash sum as a byte slice
	hashSum := hasher.Sum(nil)

	// Convert the byte slice to a hex string
	hashString := hex.EncodeToString(hashSum)

	return hashString, nil
}

func MakeSignature(file *multipart.FileHeader, name string, key string) (string, error) {
	fileData, err := file.Open()
	if err != nil {
		return "", err
	}

	defer fileData.Close()
	fileContent, err := ioutil.ReadAll(fileData)
	if err != nil {
		return "", err
	}

	hashedSignature := hashString(fileContent)
	encryptedSignature, err := EncryptRCA([]byte(hashedSignature), key)
	if err != nil {
		return "", err
	}
	signatureField := fmt.Sprintf("/Author (%s) /Signature <%s>>", name, encryptedSignature)
	appendedFileContent := append(fileContent, []byte(signatureField)...)

	err = ioutil.WriteFile(file.Filename, appendedFileContent, 0777)
	if err != nil {
		return "", err
	}

	return string(encryptedSignature), err
}

func RetrieveSignature(content []byte) (string, string, error) {
	signaturePattern := `/Author \(([^)]+)\) \/Signature <([^>]+)>`
	re := regexp.MustCompile(signaturePattern)

	// Find the first match in the PDF content
	matches := re.FindSubmatch(content)
	if len(matches) < 3 {
		return "", "", fmt.Errorf("Signature not found in PDF")
	}

	author := string(matches[1])
	encryptedSignature := string(matches[2])

	// Decrypt the signature (using a simple XOR decryption for demonstration purposes)
	decryptedSignature, err, _ := DecryptRCA([]byte(encryptedSignature), "key nih")
	if err != nil {
		return "", "", err
	}

	// // Hash the decrypted signature to obtain the original signature
	// originalSignature := hashString(decryptedSignature)

	return string(decryptedSignature), author, nil
}
