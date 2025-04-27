package gui

import (
	"COMPSEC300_PM/encryption"
	"fmt"

	"github.com/wagslane/go-password-validator"
	"github.com/webui-dev/go-webui/v2"
)

// Initialize required global variables
var DbContents string
var DbFile string
var DbPass string
var PasswordCharset string

// Function for passing database contents to frontend
func fetchDB(e webui.Event) string {
	response := DbContents
	return response
}

// Function for updating changes made to database from frontend
func updateDB(e webui.Event) error {
	updatedContents, err := webui.GetArg[string](e)
	// Call UpdateDatabase() function from encryption.go file
	err = enc.UpdateDatabase(updatedContents, DbPass, DbFile)
	if err != nil {
		fmt.Println("Error updating database: ", err)
		return err
	}
	fmt.Println("Successfully updated database contents.")
	return err
}

// Function for updating the character set used for password generation
func setCharset(e webui.Event) error {
	charset, err := webui.GetArg[string](e)
	PasswordCharset = charset
	if err != nil {
		fmt.Println("Error updating character set: ", err)
		return err
	}
	return err
}

// Function for generating a random password
func genPass(e webui.Event) string {
	length, err := webui.GetArg[int](e)

	// Generate password by calling GenerateSecurePassword() from encryption.go
	password, err := enc.GenerateSecurePassword(length, PasswordCharset)
	if err != nil {
		fmt.Println("Error generating password: ", err)
		return ""
	}
	return password
}

// Function used for checking password entropy/strength
func passStrn(e webui.Event) float64 {
	password, err := webui.GetArg[string](e)
	if err != nil {
		fmt.Println("Error checking password strength: ", err)
		return 0
	}

	// Check strength using GetEntropy() from passwordvalidator library.
	strength := passwordvalidator.GetEntropy(password)
	return strength
}

// Function for starting the GUI
func StartGui() {
	// Create a window.
	w := webui.NewWindow()
	// Bind Go functions.
	webui.Bind(w, "fetchDB", fetchDB)
	webui.Bind(w, "updateDB", updateDB)
	webui.Bind(w, "genPass", genPass)
	webui.Bind(w, "passStrn", passStrn)
	webui.Bind(w, "setCharset", setCharset)
	// Show frontend.
	w.ShowBrowser("index.html", webui.Firefox)
	// Wait until all windows get closed.
	webui.Wait()
}
