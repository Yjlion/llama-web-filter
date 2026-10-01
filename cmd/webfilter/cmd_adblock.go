package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/adblock"
	"github.com/yjlion/llama-web-filter/internal/app"
	"github.com/yjlion/llama-web-filter/internal/config"
)

func newAdBlockCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "adblock",
		Short: "Manage ad/tracker filter lists (EasyList, EasyPrivacy)",
	}
	update := &cobra.Command{Use: "update", Short: "Download the configured filter lists"}
	uf := addConfigFlags(update)
	update.RunE = func(cmd *cobra.Command, args []string) error {
		if err := config.BootstrapRuntimeFiles(uf.settingsPath); err != nil {
			return err
		}
		settings, err := config.LoadSettings(uf.settingsPath)
		if err != nil {
			return err
		}
		if settings.AdBlockDir == "" {
			settings.AdBlockDir = config.NewBootstrapSettings(uf.settingsPath).AdBlockDir
		}
		st, err := app.UpdateAdBlockLists(cmd.Context(), &settings)
		for name, size := range st.Sizes {
			fmt.Printf("%-14s %d bytes\n", name, size)
		}
		for name, e := range st.Errors {
			fmt.Printf("%-14s ERROR %s\n", name, e)
		}
		if err != nil {
			return err
		}
		fmt.Println("lists saved to", settings.AdBlockDir, "- the running proxy reloads them on the next restart or via Settings → Ad blocking → Update")
		return nil
	}
	status := &cobra.Command{Use: "status", Short: "Show which lists would be loaded"}
	sf := addConfigFlags(status)
	status.RunE = func(cmd *cobra.Command, args []string) error {
		settings, err := config.LoadSettings(sf.settingsPath)
		if err != nil {
			return err
		}
		if lists, st, ok := adblock.LoadDir(settings.AdBlockDir); ok {
			e := adblock.Build(lists...)
			fmt.Printf("downloaded lists in %s (updated %s): %+v\n", settings.AdBlockDir, st.Updated.Format("2006-01-02 15:04"), e.Stats())
			return nil
		}
		lists, err := adblock.LoadSnapshot()
		if err != nil {
			return err
		}
		fmt.Printf("embedded snapshot (%s): %+v\n", adblock.SnapshotDate, adblock.Build(lists...).Stats())
		return nil
	}
	root.AddCommand(update, status)
	return root
}
