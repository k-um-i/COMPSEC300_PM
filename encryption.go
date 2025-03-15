package main

import (
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "golang.org/x/crypto/argon2"
  "fmt"
  "io"
  "os"
)

func DeriveKey(password string) []byte {
  key := argon2.IDKey([]byte(password), []byte("testsalt"), 1, 64*1024, 4, 32)
  return key
}

// Function used for file encryption.
func EncryptFile(input_path, output_path string, key []byte) error {
  // Read and save the contents of the file
  plaintext, err := os.ReadFile(input_path)
  if err != nil {
    return err
  }

  // Initialize a new aes cipher
  block, err := aes.NewCipher(key)
  if err != nil {
    return err
  }

  // Initialize a nonce for the cipher
  nonce := make([]byte, 12) // Standard GCM nonce size
  if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
    return err
  }

  // Initialize the gcm cipher
  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return err
  }

  // Encrypt the plaintext, appending the nonce
  ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

  // Write to output file
  if err := os.WriteFile(output_path, ciphertext, 0600); err != nil{
    return err
  }

  return nil
}

// Function used for file decryption
func DecryptFile(input_path, output_path string, key []byte) error {
  // Read and save the ciphertext from the file
  ciphertext, err := os.ReadFile(input_path)
  if err != nil {
    return err
  }

  // Initialize the cipher
  block, err := aes.NewCipher(key)
  if err != nil {
    return err
  }

  // Initialize the gcm cipher
  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return err
  }

  // Separate the nonce and ciphertext
  nonce := ciphertext[:gcm.NonceSize()]
  ciphertext = ciphertext[gcm.NonceSize():]

  // Decrypt the ciphertext
  plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
  if err != nil {
    return err
  }

  // Write the plaintext to the output file
  if err := os.WriteFile(output_path, plaintext, 0600); err != nil {
    return err
  }

  return nil
}

func main() {
  // ##### TESTING #####
  /*
  key := make([]byte, 32)
  if _, err := io.ReadFull(rand.Reader, key); err != nil {
    fmt.Println("Failed to generate key:", err)
    return
  }
  */

  mode := os.Args[1]
  password := os.Args[2]

  input_path := os.Args[3]
  output_path := os.Args[4]

  key := DeriveKey(password)

  var err error
  if mode == "encrypt" {
    err = EncryptFile(input_path, output_path, key)
  } else if mode == "decrypt" {
    err = DecryptFile(input_path, output_path, key)
  } else {
    fmt.Println("Invalid mode, use 'encrypt' or 'decrypt'.")
  }

  if err != nil {
    fmt.Println("Operation failed:", err)
  } else {
    fmt.Println("Operation successful.")
  }


  /*
  if err := EncryptFile(input_path, output_path, key); err != nil{
    fmt.Println("Encryption failed:", err)
  }

  fmt.Println("Press enter to run decryption...")
  fmt.Scanln()

  input_path = output_path
  output_path = "./testfiledec.txt"

  if err := DecryptFile(input_path, output_path, key); err != nil {
    fmt.Println("Decryption failed:", err)
  }
  */
}

