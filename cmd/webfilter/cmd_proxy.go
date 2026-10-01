package main

import "github.com/spf13/cobra"

func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run only the MITM filtering proxy engine",
	}
	f := addConfigFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runProxy(cmd.Context(), f.settingsPath)
	}
	return cmd
}
