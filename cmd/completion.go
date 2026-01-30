package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// completionCmd represents the completion command.
var completionCmd = &cobra.Command{
	Use:     "completion [bash|zsh|fish|powershell]",
	Short:   "Generate completion script",
	GroupID: "utility",
	Long: `To load completions:

Bash:
  $ source <(opndossier completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ opndossier completion bash > /etc/bash_completion.d/opndossier
  # macOS:
  $ opndossier completion bash > $(brew --prefix)/etc/bash_completion.d/opndossier

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ opndossier completion zsh > "${fpath[1]}/_opndossier"

  # You will need to start a new shell for this setup to take effect.

fish:
  $ opndossier completion fish | source

  # To load completions for each session, execute once:
  $ opndossier completion fish > ~/.config/fish/completions/opndossier.fish

PowerShell:
  PS> opndossier completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> opndossier completion powershell > opndossier.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletion(os.Stdout)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
