package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

func hashString(input []byte) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write(input)
	if err != nil {
		return "", errors.New("error hashing")
	}

	hashSum := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashSum)
	return hashString, nil
}

func SignWithPrivate(message []byte, privateKeyStr string) ([]byte, error) {
	privateKey, err := stringToPrivateKey(privateKeyStr)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, message)
	if err != nil {
		return nil, fmt.Errorf("error signing message: %w", err)
	}
	return signature, nil
}

func VerifyWithPublic(message, signature []byte, publicKeyStr string) error {
	publicKey, err := stringToPublicKey(publicKeyStr)
	verif := rsa.VerifyPKCS1v15(publicKey, 0, message, signature)
	if verif != nil {
		return fmt.Errorf("verification failed: %w", err)
	}
	return nil
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
