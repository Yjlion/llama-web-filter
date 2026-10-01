package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/policy/nlp"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
)

func newRulesCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "rules",
		Short: "Manage natural-language policy rules (rules.json)",
	}

	list := &cobra.Command{Use: "list", Short: "List rules"}
	lf := addConfigFlags(list)
	list.RunE = func(cmd *cobra.Command, args []string) error {
		st := rules.NewStore(rules.PathFor(lf.settingsPath))
		f, err := st.Load()
		if err != nil {
			return err
		}
		if len(f.Rules) == 0 {
			fmt.Println("no rules")
		}
		for _, r := range f.Rules {
			state := "on "
			if !r.Enabled {
				state = "off"
			}
			fmt.Printf("%s  %s  %s\n", r.ID, state, rules.Describe(r))
		}
		return nil
	}

	add := &cobra.Command{
		Use:   "add <sentence>",
		Short: "Compile a sentence into a rule and save it (use --dry-run to only show it)",
		Args:  cobra.MinimumNArgs(1),
	}
	af := addConfigFlags(add)
	var dryRun, yes bool
	var external string
	add.Flags().BoolVar(&dryRun, "dry-run", false, "show the compiled rule without saving")
	add.Flags().BoolVarP(&yes, "yes", "y", false, "save without asking for confirmation")
	add.Flags().StringVar(&external, "llm-url", "", "OpenAI-compatible server to compile with (default: settings llm.external_url, or the parser)")
	add.RunE = func(cmd *cobra.Command, args []string) error {
		text := strings.Join(args, " ")
		settings, err := config.LoadSettings(af.settingsPath)
		if err != nil {
			return err
		}
		st := rules.NewStore(rules.PathFor(af.settingsPath))
		f, err := st.Load()
		if err != nil {
			return err
		}
		url := external
		if url == "" {
			url = settings.LLM.ExternalURL
		}
		comp := &nlp.Compiler{Devices: f.Devices}
		if url != "" {
			cli := client.New(url)
			comp.Client = func() *client.Client { return cli }
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(settings.LLM.Budget.CompileMs)*time.Millisecond)
		defer cancel()
		out, err := comp.Compile(ctx, text)
		if err != nil {
			return err
		}
		fmt.Println(out.Summary)
		for _, w := range out.Warnings {
			fmt.Println("  warning:", w)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out.Rule)
		if dryRun {
			return nil
		}
		if !yes {
			fmt.Print("Save this rule? [y/N] ")
			var answer string
			_, _ = fmt.Scanln(&answer)
			if !strings.HasPrefix(strings.ToLower(answer), "y") {
				fmt.Println("not saved")
				return nil
			}
		}
		saved, err := st.Add(out.Rule)
		if err != nil {
			return err
		}
		fmt.Println("saved", saved.ID)
		return nil
	}

	remove := &cobra.Command{Use: "remove <id>", Short: "Delete a rule", Args: cobra.ExactArgs(1)}
	rf := addConfigFlags(remove)
	remove.RunE = func(cmd *cobra.Command, args []string) error {
		return rules.NewStore(rules.PathFor(rf.settingsPath)).Delete(args[0])
	}

	root.AddCommand(list, add, remove)
	return root
}
