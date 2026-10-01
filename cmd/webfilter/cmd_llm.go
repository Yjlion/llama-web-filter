package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/llm"
	"github.com/yjlion/llama-web-filter/internal/llm/catalog"
	"github.com/yjlion/llama-web-filter/internal/llm/runtime"
)

func newLLMCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "llm",
		Short: "Manage the local edge-LLM runtime and models",
	}

	status := &cobra.Command{Use: "status", Short: "Show runtime, model and download state"}
	sf := addConfigFlags(status)
	var asJSON bool
	status.Flags().BoolVar(&asJSON, "json", false, "print the raw status JSON")
	status.RunE = func(cmd *cobra.Command, args []string) error {
		svc, err := loadLLMService(sf.settingsPath)
		if err != nil {
			return err
		}
		st := svc.Status()
		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(st)
		}
		rtMissing, mMissing := svc.Missing()
		fmt.Printf("enabled:    %v\n", st.Enabled)
		fmt.Printf("model:      %s (%s)\n", st.Model, st.ModelName)
		fmt.Printf("accel:      %s\n", st.Accel)
		fmt.Printf("data dir:   %s\n", st.DataDir)
		fmt.Printf("runtime:    llama.cpp %s installed=%v\n", st.RuntimeTag, !rtMissing)
		fmt.Printf("model file: installed=%v\n", !mMissing)
		if st.External != "" {
			fmt.Printf("external:   %s\n", st.External)
		}
		if len(st.Installed) > 0 {
			fmt.Println("installed models:")
			for _, m := range st.Installed {
				fmt.Printf("  %-14s %s (%d MB, vision=%v)\n", m.ID, m.ModelFile, m.SizeBytes>>20, m.Vision)
			}
		}
		if rtMissing || mMissing {
			fmt.Println("\nrun `webfilter llm download` to fetch what is missing")
		}
		return nil
	}

	models := &cobra.Command{Use: "models", Short: "List the model catalog"}
	models.RunE = func(cmd *cobra.Command, args []string) error {
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tVISION\t~SIZE\tMIN RAM\tDESCRIPTION")
		for _, m := range catalog.All() {
			fmt.Fprintf(tw, "%s\t%s\t%v\t%d MB\t%d MB\t%s\n", m.ID, m.Name, m.Vision, m.ApproxSizeMB, m.MinRAMMB, m.Description)
		}
		return tw.Flush()
	}

	download := &cobra.Command{
		Use:   "download [model-id]",
		Short: "Download the llama.cpp runtime and a model (default: the configured model)",
		Args:  cobra.MaximumNArgs(1),
	}
	df := addConfigFlags(download)
	download.RunE = func(cmd *cobra.Command, args []string) error {
		svc, err := loadLLMService(df.settingsPath)
		if err != nil {
			return err
		}
		id := ""
		if len(args) == 1 {
			id = args[0]
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := svc.Download(ctx, id); err != nil {
			return err
		}
		return watchDownload(ctx, svc)
	}

	remove := &cobra.Command{Use: "remove <model-id>", Short: "Delete an installed model", Args: cobra.ExactArgs(1)}
	rf := addConfigFlags(remove)
	remove.RunE = func(cmd *cobra.Command, args []string) error {
		svc, err := loadLLMService(rf.settingsPath)
		if err != nil {
			return err
		}
		return svc.RemoveModel(args[0])
	}

	serve := &cobra.Command{
		Use:   "serve",
		Short: "Run llama-server in the foreground with the configured model (for debugging)",
	}
	svf := addConfigFlags(serve)
	serve.RunE = func(cmd *cobra.Command, args []string) error {
		svc, err := loadLLMService(svf.settingsPath)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if rt, m := svc.Missing(); rt || m {
			return fmt.Errorf("runtime or model missing; run `webfilter llm download` first")
		}
		if err := svc.Start(ctx); err != nil {
			return err
		}
		st := svc.Status()
		if st.Server != nil {
			fmt.Printf("llama-server running at %s (pid %d); Ctrl-C to stop\n", st.Server.BaseURL, st.Server.PID)
		}
		<-ctx.Done()
		svc.Stop()
		return nil
	}

	probe := &cobra.Command{Use: "probe", Short: "Show which llama.cpp build this machine would use"}
	probe.RunE = func(cmd *cobra.Command, args []string) error {
		accel := runtime.ProbeAccel()
		fmt.Printf("accel: %s\n", accel)
		if a, ok := runtime.AssetFor(runtime.PinnedTag, goos(), goarch(), accel); ok {
			fmt.Printf("asset: %s\n", a.Name)
			fmt.Printf("url:   %s\n", a.URL)
		} else {
			fmt.Println("no prebuilt available for this platform")
		}
		return nil
	}

	root.AddCommand(status, models, download, remove, serve, probe)
	return root
}

func loadLLMService(settingsPath string) (*llm.Service, error) {
	if err := config.BootstrapRuntimeFiles(settingsPath); err != nil {
		return nil, err
	}
	settings, err := config.LoadSettings(settingsPath)
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}
	cfg := settings.LLM
	if strings.TrimSpace(cfg.DataDir) == "" {
		cfg.DataDir = config.NewBootstrapSettings(settingsPath).LLM.DataDir
	}
	return llm.New(cfg), nil
}

func watchDownload(ctx context.Context, svc *llm.Service) error {
	last := ""
	for {
		st := svc.Status()
		d := st.Download
		line := d.Step
		if d.BytesTot > 0 {
			line = fmt.Sprintf("%s  %5.1f%%  %d/%d MB", d.Step, d.Percent, d.BytesDone>>20, d.BytesTot>>20)
		}
		if line != last {
			fmt.Printf("\r\033[K%s", line)
			last = line
		}
		if !d.Active {
			fmt.Println()
			if d.Error != "" {
				return fmt.Errorf("download failed: %s", d.Error)
			}
			fmt.Printf("done in %.0fs\n", d.Seconds)
			return nil
		}
		select {
		case <-ctx.Done():
			svc.CancelDownload()
			fmt.Println("\ncancelled")
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}
