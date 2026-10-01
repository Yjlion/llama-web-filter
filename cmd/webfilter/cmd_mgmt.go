package main

import "github.com/spf13/cobra"

func newMgmtCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mgmt",
		Short: "Run only the management HTTP server (API + web UI)",
	}
	f := addConfigFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runMgmt(cmd.Context(), f.settingsPath)
	}
	return cmd
}
