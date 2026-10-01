//go:build !windows

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// runAsWindowsServiceIfApplicable is a no-op on non-Windows platforms:
// `run` always executes in the foreground here. Use systemd on Linux (unit
// templates + an install script live under packaging/) instead of a
// service-management subcommand.
func runAsWindowsServiceIfApplicable(settingsPath string) (handled bool, err error) {
	return false, nil
}

// newServiceCmd is a friendly stub on non-Windows platforms, pointing at the
// systemd equivalent rather than silently omitting the `service` subcommand
// (which would just look like a typo to a user coming from the Windows
// docs).
func newServiceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "service",
		Short: "(Windows only) manage WebFilter Proxy as a Windows service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("`webfilter service` is Windows-only; on Linux, install the systemd unit under packaging/ instead (see packaging/README.md)")
		},
	}
}
