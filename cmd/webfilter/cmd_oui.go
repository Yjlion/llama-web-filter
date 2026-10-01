package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/neighbors"
)

// manufURL is the Wireshark-maintained IEEE OUI dataset, same source
// scripts/update_oui.sh downloads.
const manufURL = "https://www.wireshark.org/download/automated/data/manuf"

func newOuiCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "oui",
		Short: "Manage the IEEE OUI vendor lookup table override",
	}
	update := &cobra.Command{
		Use:   "update",
		Short: "Refresh the OUI vendor lookup table override",
	}
	f := addConfigFlags(update)
	update.RunE = func(cmd *cobra.Command, args []string) error {
		return runOuiUpdate(f.settingsPath)
	}
	root.AddCommand(update)
	return root
}

func runOuiUpdate(settingsPath string) error {
	settings, err := config.LoadSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}
	path := settings.OuiPath
	if path == "" {
		path = neighbors.DefaultOuiPath
	}

	fmt.Printf("[oui] downloading %s ...\n", manufURL)
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(manufURL)
	if err != nil {
		return fmt.Errorf("download manuf list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download manuf list: unexpected status %d", resp.StatusCode)
	}

	table := neighbors.ParseWiresharkManuf(resp.Body)
	if len(table) == 0 {
		return fmt.Errorf("parsed 0 entries from %s - source format may have changed", manufURL)
	}

	if err := neighbors.WriteOuiFile(path, manufURL, table); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	fmt.Printf("[oui] done: %d entries written to %s\n", len(table), path)
	return nil
}
