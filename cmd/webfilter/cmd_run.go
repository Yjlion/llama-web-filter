package main

import (
	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run both the proxy engine and the management server in one process",
	}
	f := addConfigFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// On Windows, this is also the entrypoint the Service Control
		// Manager launches ("run --settings <path>") when installed via
		// `webfilter service install` - handled==true means it dispatched
		// into svc.Run's service loop instead of a normal foreground run.
		if handled, err := runAsWindowsServiceIfApplicable(f.settingsPath); handled {
			return err
		}
		return runProxyAndMgmt(cmd.Context(), f.settingsPath)
	}
	return cmd
}
