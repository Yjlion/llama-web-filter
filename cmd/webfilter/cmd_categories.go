package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/categories"
	"github.com/yjlion/llama-web-filter/internal/config"
)

func newCategoriesCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "categories",
		Short: "Manage shared site-category blocklists",
	}
	update := &cobra.Command{
		Use:   "update",
		Short: "Download and refresh site-category blocklists",
	}
	f := addConfigFlags(update)
	var url, keep string
	update.Flags().StringVar(&url, "url", categories.DefaultUpdateURL,
		"source tarball URL (IPFire squidGuard format: one top-level dir, one subdir per category with a domains file)")
	update.Flags().StringVar(&keep, "keep", "",
		"comma-separated category whitelist (default: all categories in the archive)")
	update.RunE = func(cmd *cobra.Command, args []string) error {
		return runCategoriesUpdate(f.settingsPath, url, keep)
	}
	root.AddCommand(update)
	return root
}

func runCategoriesUpdate(settingsPath, url, keep string) error {
	settings, err := config.LoadSettings(settingsPath)
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}
	dest := settings.CategoriesDir
	if dest == "" {
		dest = "./categories"
	}

	fmt.Printf("[categories] downloading %s ...\n", url)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download blocklist: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download blocklist: unexpected status %d", resp.StatusCode)
	}

	fmt.Println("[categories] extracting ...")
	lists, err := categories.ExtractDomainLists(resp.Body)
	if err != nil {
		return fmt.Errorf("extract archive: %w", err)
	}

	keepSet := map[string]bool{}
	for _, name := range strings.Split(keep, ",") {
		if name = strings.TrimSpace(name); name != "" {
			keepSet[name] = true
		}
	}

	metas, err := categories.WriteCategories(dest, url, lists, keepSet)
	if err != nil {
		return fmt.Errorf("write categories: %w", err)
	}

	for _, m := range metas {
		fmt.Printf("[categories] %-12s %8d domains\n", m.Name, m.Count)
	}
	fmt.Printf("[categories] done: %d categories written to %s\n", len(metas), dest)
	return nil
}
