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

// Main function that takes two commandline arguments.
//  1. Command (open | create)
//     open is used for opening an existing password database
//     create is used for creating an empty password database
//  2. filename
//     specifies the filename of the database to be opened/created
func main() {
	// Check that a command argument is present
	if len(os.Args) < 2 {
		fmt.Println("Usage: [open|create] <filename>")
		os.Exit(1)
	}

	// Fetch command from args
	command := os.Args[1]

	// Switch case for command (open | create)
	switch command {
	case "open":
		openCmd := flag.NewFlagSet("open", flag.ExitOnError)
		openCmd.Parse(os.Args[2:])

		// Check that filename is provided
		if openCmd.NArg() < 1 {
			fmt.Println("Usage: open <filename>")
			os.Exit(1)
		}
		filename := openCmd.Arg(0)

		// Check that specified file exists
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			fmt.Printf("Error: File \"%s\" does not exist.\n", filename)
			os.Exit(1)
		}

		// Prompt user for database password
		fmt.Print("Enter password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password: ", err)
		}
		fmt.Println()

		password := string(passwordBytes)

		// Read database file contents
		fileContent, err := os.ReadFile(filename)
		if err != nil {
			log.Fatalf("Error reading file %s: %v\n", filename, err)
		}

		// Attempt to decrypt database contents
		dbContents, err := enc.DecryptContents(fileContent, password)
		if err != nil {
			log.Fatalf("Error decrypting database: %v\n", err)
		}

		// Set required variables and start GUI
		fmt.Println("Database opened successfully.")
		gui.DbContents = dbContents
		gui.DbFile = filename
		gui.DbPass = password
		gui.StartGui()

	case "create":
		createCmd := flag.NewFlagSet("create", flag.ExitOnError)
		createCmd.Parse(os.Args[2:])

		// Check that filename arg is present
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
			log.Fatal("Error reading password: ", err)
		}
		fmt.Println()

		fmt.Print("Confirm password: ")
		pass2, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal("Error reading password: ", err)
		}
		fmt.Println()

		// Check that provided passwords match
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

		// Set required DB variables and start GUI
		fmt.Println("Database created successfully.")
		gui.DbContents = xml
		gui.DbFile = filename
		gui.DbPass = password
		gui.StartGui()

	default:
		// Default case if user provided command is not recognized
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Usage: [open|create] <filename>")
		os.Exit(1)
	}
}
