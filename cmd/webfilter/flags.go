package main

import "github.com/spf13/cobra"

// configFlags are the flags shared by every subcommand that reads
// config/settings.json (run, proxy, mgmt). settingsPath mirrors the Python
// original's convention of running from a project root containing
// config/settings.json, policies/, certs/, categories/, logs/ as relative
// dirs (paths inside settings.json itself remain relative to the process's
// working directory, matching shared/models.py's GlobalSettings defaults).
type configFlags struct {
	settingsPath string
}

func addConfigFlags(cmd *cobra.Command) *configFlags {
	f := &configFlags{}
	cmd.Flags().StringVar(&f.settingsPath, "settings", "config/settings.json",
		"path to settings.json")
	return f
}
