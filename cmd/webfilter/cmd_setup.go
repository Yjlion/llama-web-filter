package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/llm/catalog"
	"github.com/yjlion/llama-web-filter/internal/llm/runtime"
)

// newSetupCmd is the first-run wizard: create the settings and default
// policy, pick a model, download the llama.cpp runtime and the model, and
// print how to point browsers at the proxy.
func newSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "First-run setup: create config, choose and download the local model",
	}
	f := addConfigFlags(cmd)
	var model string
	var yes, skipDownload bool
	cmd.Flags().StringVar(&model, "model", "", "catalog model id to install (default: ask, or "+string(catalogDefault())+" with --yes)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask; accept defaults")
	cmd.Flags().BoolVar(&skipDownload, "skip-download", false, "only write config files")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if err := config.BootstrapRuntimeFiles(f.settingsPath); err != nil {
			return err
		}
		settings, err := config.LoadSettings(f.settingsPath)
		if err != nil {
			return err
		}
		if settings.LLM.DataDir == "" {
			settings.LLM.DataDir = config.NewBootstrapSettings(f.settingsPath).LLM.DataDir
		}
		fmt.Printf("settings:   %s\n", f.settingsPath)
		fmt.Printf("policies:   %s\n", settings.PoliciesDir)
		fmt.Printf("llm data:   %s\n", settings.LLM.DataDir)
		fmt.Printf("accel:      %s (llama.cpp %s)\n\n", runtime.ResolveAccel(settings.LLM.Accel), runtime.PinnedTag)

		in := bufio.NewReader(os.Stdin)
		if model == "" {
			model = settings.LLM.Model
			if !yes {
				fmt.Println("Models:")
				for i, m := range catalog.All() {
					mark := " "
					if m.ID == settings.LLM.Model {
						mark = "*"
					}
					vision := "text+image"
					if !m.Vision {
						vision = "text only"
					}
					fmt.Printf(" %s %d) %-14s %-32s %s, ~%d MB, needs ~%d MB RAM\n", mark, i+1, m.ID, m.Name, vision, m.ApproxSizeMB, m.MinRAMMB)
				}
				fmt.Printf("Choose a model [%s]: ", settings.LLM.Model)
				line, _ := in.ReadString('\n')
				line = strings.TrimSpace(line)
				if line != "" {
					var n int
					if _, err := fmt.Sscanf(line, "%d", &n); err == nil && n >= 1 && n <= len(catalog.All()) {
						model = catalog.All()[n-1].ID
					} else {
						model = line
					}
				}
			}
		}
		m, ok := catalog.Lookup(model)
		if !ok {
			return fmt.Errorf("unknown model %q (known: %v)", model, catalog.IDs())
		}
		if settings.LLM.Model != m.ID || settings.LLM.DataDir == "" {
			settings.LLM.Model = m.ID
			if err := config.SaveSettings(f.settingsPath, settings); err != nil {
				return err
			}
			fmt.Printf("model set to %s\n", m.ID)
		}
		if skipDownload {
			return nil
		}
		svc, err := loadLLMService(f.settingsPath)
		if err != nil {
			return err
		}
		if rt, mm := svc.Missing(); !rt && !mm {
			fmt.Println("runtime and model already installed")
		} else {
			if !yes {
				fmt.Printf("Download the llama.cpp runtime and %s (~%d MB)? [Y/n] ", m.ID, m.ApproxSizeMB)
				line, _ := in.ReadString('\n')
				if l := strings.ToLower(strings.TrimSpace(line)); l != "" && l != "y" && l != "yes" {
					fmt.Println("skipped; run `webfilter llm download` later")
					return nil
				}
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if err := svc.Download(ctx, m.ID); err != nil {
				return err
			}
			if err := watchDownload(ctx, svc); err != nil {
				return err
			}
		}
		fmt.Println()
		fmt.Println("Done. Start the filter with:")
		fmt.Printf("  webfilter run --settings %s\n", f.settingsPath)
		fmt.Println("then open the management UI, download the CA certificate from the Settings page and")
		fmt.Println("install it on each device, and point devices at the proxy (or use the PAC file).")
		return nil
	}
	return cmd
}

func catalogDefault() string {
	for _, m := range catalog.All() {
		return m.ID
	}
	return ""
}
