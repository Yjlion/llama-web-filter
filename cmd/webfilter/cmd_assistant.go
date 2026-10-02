package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/config"
	"github.com/yjlion/llama-web-filter/internal/llm/client"
	"github.com/yjlion/llama-web-filter/internal/policy/assistant"
	"github.com/yjlion/llama-web-filter/internal/policy/rules"
)

func newAssistantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assistant <request>",
		Short: "Ask the model to change the policies in plain language, e.g. \"block social media for the kids tablet after 9pm\"",
		Args:  cobra.MinimumNArgs(1),
	}
	f := addConfigFlags(cmd)
	var yes bool
	var external string
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "apply the proposed changes without asking")
	cmd.Flags().StringVar(&external, "llm-url", "", "OpenAI-compatible server to ask (default: settings llm.external_url, else the local runtime's port)")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		settings, err := config.LoadSettings(f.settingsPath)
		if err != nil {
			return err
		}
		url := external
		if url == "" {
			url = settings.LLM.ExternalURL
		}
		if url == "" && settings.LLM.Port > 0 {
			// `webfilter run` is serving the model on this port.
			url = fmt.Sprintf("http://127.0.0.1:%d", settings.LLM.Port)
		}
		if url == "" {
			return fmt.Errorf("no model to ask: pass --llm-url, set llm.external_url or llm.port, or use the Assistant page while `webfilter run` is running")
		}
		doc, err := rules.NewStore(rules.PathFor(f.settingsPath)).Load()
		if err != nil {
			return err
		}
		cli := client.New(url)
		a := &assistant.Assistant{
			Client:   func() *client.Client { return cli },
			Policies: config.NewPolicyStore(settings.PoliciesDir),
			Devices:  doc.Devices,
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(settings.LLM.Budget.CompileMs)*time.Millisecond)
		defer cancel()
		p, err := a.Ask(ctx, nil, strings.Join(args, " "))
		if err != nil {
			return err
		}
		fmt.Println(p.Reply)
		var changes []assistant.Change
		for i, c := range p.Changes {
			mark := "+"
			if c.Error != "" {
				mark = "x"
			}
			fmt.Printf("  %s %d. %s\n", mark, i+1, c.Summary)
			if c.Error != "" {
				fmt.Println("       cannot apply:", c.Error)
				continue
			}
			for _, w := range c.Warnings {
				fmt.Println("       warning:", w)
			}
			changes = append(changes, c.Change)
		}
		if len(changes) == 0 {
			return nil
		}
		if !yes {
			fmt.Print("Apply these changes? [y/N] ")
			var answer string
			_, _ = fmt.Scanln(&answer)
			if !strings.HasPrefix(strings.ToLower(answer), "y") {
				fmt.Println("nothing changed")
				return nil
			}
		}
		res, err := a.Apply(changes)
		for _, n := range res.Created {
			fmt.Println("created policy", n)
		}
		for _, n := range res.Updated {
			fmt.Println("updated policy", n)
		}
		for _, n := range res.Deleted {
			fmt.Println("deleted policy", n)
		}
		for _, n := range res.Skipped {
			fmt.Println("skipped:", n)
		}
		return err
	}
	return cmd
}
