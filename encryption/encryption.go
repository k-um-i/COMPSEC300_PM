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

// Function for deriving a secure encryption key from master password
func DeriveKey(password string, salt []byte) []byte {
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return key
}

// Function for encrypting database contents
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

// Function for decrypting database contents
func DecryptContents(contents []byte, password string) (decContents string, err error) {
	ciphertext := contents

	// Extract salt from ciphertext
	salt := ciphertext[:16]
	ciphertext = ciphertext[16:]
	// Derive key with provided password and extracted salt
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

// Function used for updating changes into the encrypted database file
func UpdateDatabase(contents, password, dbFile string) error {
	// Generate new secure salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	// Derive new secure key using provided password and generated salt
	key := DeriveKey(password, salt)
	// Encrypt updated contents using EncryptContents()
	encryptedContents, _ := EncryptContents(contents, key, salt)
	// Write salt to start of file
	if err := os.WriteFile(dbFile, salt, 0600); err != nil {
		return err
	}
	// Open file for appending
	f, err := os.OpenFile(dbFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	// Write newly encrypted contents to file
	if _, err := f.Write(encryptedContents); err != nil {
		return err
	}

	return nil
}

// Function for generating a secure password
func GenerateSecurePassword(length int, charset string) (string, error) {
	// Initialize password variable with specified length
	password := make([]byte, length)

	// Generate specified number of random characters
	// Characters are generated from currently set character set (charset)
	for i := 0; i < length; i++ {
		char, err := randomCharFromSet(charset)
		if err != nil {
			return "", err
		}
		password[i] = char
	}

	// Shuffle generated password
	shuffle(password)

	// Return generated password
	return string(password), nil
}

// Function for generating a random character from specified character set
func randomCharFromSet(set string) (byte, error) {
	// Generate secure random int
	num, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, err
	}
	return set[num.Int64()], nil
}

// Function for shuffling data
func shuffle(data []byte) {
	// Iterate through data
	for i := range data {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(data))))
		j := int(jBig.Int64())
		data[i], data[j] = data[j], data[i]
	}
}
