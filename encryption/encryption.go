package enc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/argon2"
)

func DeriveKey(password string, salt []byte) []byte {
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return key
}

func EncryptContents(contents string, key []byte, salt []byte) (encContents []byte, err error) {
	// Initialize a new aes cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Initialize a nonce for the cipher
	nonce := make([]byte, 12) // Standard GCM nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Initialize the gcm cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Encrypt the plaintext, appending the nonce
	contentsBytes := []byte(contents)
	ciphertext := gcm.Seal(nonce, nonce, contentsBytes, nil)

	return ciphertext, nil
}

func DecryptContents(contents []byte, password string) (decContents string, err error) {
	ciphertext := contents

	salt := ciphertext[:16]
	ciphertext = ciphertext[16:]
	key := DeriveKey(password, salt)

	// Initialize the cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// Initialize the gcm cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Separate the nonce and ciphertext
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	// Return the plaintext
	return string(plaintext), err
}

func UpdateDatabase(contents, password, dbFile string) error {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key := DeriveKey(password, salt)
	encryptedContents, _ := EncryptContents(contents, key, salt)
	if err := os.WriteFile(dbFile, salt, 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(dbFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(encryptedContents); err != nil {
		return err
	}

	return nil
}

func GenerateSecurePassword(length int) (string, error) {
	lower := "abcdefghijklmnopqrstuvwxyz"
	upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	special := "!@#$%^*()-_=+[]{}?/|"
	all := lower + upper + digits + special
	categories := []string{lower, upper, digits, special}
	password := make([]byte, length)

	for i, cat := range categories {
		char, err := randomCharFromSet(cat)
		if err != nil {
			return "", err
		}
		password[i] = char
	}
	for i := 4; i < length; i++ {
		char, err := randomCharFromSet(all)
		if err != nil {
			return "", err
		}
		password[i] = char
	}

	shuffle(password)

	return string(password), nil
}

func randomCharFromSet(set string) (byte, error) {
	num, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[num.Int64()], nil
}

func shuffle(data []byte) {
	for i := range data {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(data))))
		j := int(jBig.Int64())
		data[i], data[j] = data[j], data[i]
	}
}
