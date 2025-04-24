package gui

import (
	"COMPSEC300_PM/encryption"
	"fmt"

	"github.com/wagslane/go-password-validator"
	"github.com/webui-dev/go-webui/v2"
)

var DbContents string
var DbFile string
var DbPass string

func fetchDB(e webui.Event) string {
	response := DbContents
	return response
}

func updateDB(e webui.Event) error {
	updatedContents, err := webui.GetArg[string](e)
	err = enc.UpdateDatabase(updatedContents, DbPass, DbFile)
	if err != nil {
		fmt.Println("Error updating database: ", err)
		return err
	}
	fmt.Println("Successfully updated database contents.")
	return err
}

func genPass(e webui.Event) string {
	password, err := enc.GenerateSecurePassword(20)
	if err != nil {
		fmt.Println("Error generating password: ", err)
		return ""
	}
	return password
}

func passStrn(e webui.Event) float64 {
	password, err := webui.GetArg[string](e)
	if err != nil {
		fmt.Println("Error checking password strength: ", err)
		return 0
	}
	strength := passwordvalidator.GetEntropy(password)
	return strength
}

func StartGui() {
	// Create a window.
	w := webui.NewWindow()
	// Bind a Go function.
	webui.Bind(w, "fetchDB", fetchDB)
	webui.Bind(w, "updateDB", updateDB)
	webui.Bind(w, "genPass", genPass)
	webui.Bind(w, "passStrn", passStrn)
	// Show frontend.
	w.ShowBrowser("index.html", webui.Firefox)
	// Wait until all windows get closed.
	webui.Wait()
}
