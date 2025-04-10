package gui

import (
	"COMPSEC300_PM/encryption"
	"fmt"

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
	fmt.Println(updatedContents)
	err = enc.UpdateDatabase(updatedContents, DbPass, DbFile)
	if err != nil {
		fmt.Println("Error updating database: ", err)
	}
	return err
}

func StartGui() {
	// Create a window.
	w := webui.NewWindow()
	// Bind a Go function.
	webui.Bind(w, "fetchDB", fetchDB)
	webui.Bind(w, "updateDB", updateDB)
	// Show frontend.
	w.ShowBrowser("index.html", webui.Firefox)
	// Wait until all windows get closed.
	webui.Wait()
}
