// main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"COMPSEC300_PM/encryption"
	"COMPSEC300_PM/gui"
	"golang.org/x/term"
	"syscall"
)

var DbPass string

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: [open|create] <filename>")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "open":
		openCmd := flag.NewFlagSet("open", flag.ExitOnError)
		openCmd.Parse(os.Args[2:])

		if openCmd.NArg() < 1 {
			fmt.Println("Usage: open <filename>")
			os.Exit(1)
		}
		filename := openCmd.Arg(0)

		if _, err := os.Stat(filename); os.IsNotExist(err) {
			fmt.Printf("Error: File \"%s\" does not exist.\n", filename)
			os.Exit(1)
		}

		fmt.Print("Enter password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password:", err)
		}
		fmt.Println()

		password := string(passwordBytes)

		fileContent, err := os.ReadFile(filename)
		if err != nil {
			log.Fatalf("Error reading file %s: %v\n", filename, err)
		}

		dbContents, err := enc.DecryptContents(fileContent, password)
		if err != nil {
			log.Fatalf("Error decrypting database: %v\n", err)
		}

		fmt.Println(dbContents)
		fmt.Println("Database opened successfully.")
		gui.DbContents = dbContents
		gui.DbFile = filename
		gui.DbPass = password
		gui.StartGui()

	case "create":
		createCmd := flag.NewFlagSet("create", flag.ExitOnError)
		createCmd.Parse(os.Args[2:])

		if createCmd.NArg() < 1 {
			fmt.Println("Usage: create <filename>")
			os.Exit(1)
		}
		filename := createCmd.Arg(0)

		// Check if file already exists
		if _, err := os.Stat(filename); err == nil {
			fmt.Printf("Error: File \"%s\" already exists.\n", filename)
			os.Exit(1)
		}

		// Prompt for password and confirm
		fmt.Print("Enter new password: ")
		pass1, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password:", err)
		}
		fmt.Println()

		fmt.Print("Confirm password: ")
		pass2, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password:", err)
		}
		fmt.Println()

		if string(pass1) != string(pass2) {
			fmt.Println("Error: Passwords do not match.")
			os.Exit(1)
		}

		password := string(pass1)

		// Create an empty XML database structure
		xml := `<PasswordManager>
</PasswordManager>`

		// Encrypt it
		err = enc.UpdateDatabase(xml, password, filename)
		if err != nil {
			log.Fatalf("Error creating database: %v\n", err)
		}

		fmt.Println("Database created successfully.")
		gui.DbContents = xml
		gui.DbFile = filename
		gui.DbPass = password
		gui.StartGui()

	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Usage: [open|create] <filename>")
		os.Exit(1)
	}
}
