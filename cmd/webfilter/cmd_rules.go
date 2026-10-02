package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yjlion/llama-web-filter/internal/policy/rules"
)

func newRulesCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "rules",
		Short: "List or remove sentence rules saved by earlier versions (use `webfilter assistant` for changes)",
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

	remove := &cobra.Command{Use: "remove <id>", Short: "Delete a rule", Args: cobra.ExactArgs(1)}
	rf := addConfigFlags(remove)
	remove.RunE = func(cmd *cobra.Command, args []string) error {
		return rules.NewStore(rules.PathFor(rf.settingsPath)).Delete(args[0])
	}

	root.AddCommand(list, remove)
	return root
}
