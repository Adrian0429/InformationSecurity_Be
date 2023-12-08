package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

func HashString(input []byte) (string, error) {
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
