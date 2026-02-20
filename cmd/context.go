// Package cmd provides the command-line interface for opnDossier.
package cmd

import (
	"context"

	"github.com/EvilBit-Labs/opnDossier/internal/config"
	"github.com/EvilBit-Labs/opnDossier/internal/logging"
	"github.com/spf13/cobra"
)

// CommandContext encapsulates shared state for all CLI commands.
// It is set on the cobra.Command context during PersistentPreRunE
// and provides explicit dependency injection for configuration and logging.
//
// This pattern replaces direct access to package-level globals,
// making dependencies explicit and testing easier.
type CommandContext struct {
	// Config holds the application's configuration loaded from file, environment, or flags.
	Config *config.Config

	// Logger is the application's structured logger instance.
	Logger *logging.Logger
}

// contextKey is the type for context keys to avoid collisions with other packages.
type contextKey string

// cmdContextKey is the key used to store CommandContext in context.Context.
const cmdContextKey contextKey = "opnDossierCmdContext"

// GetCommandContext retrieves the CommandContext from a cobra.Command's context.
// Returns nil if the context is not set or does not contain a CommandContext.
//
// Example usage in a command's RunE function:
//
//	func runMyCommand(cmd *cobra.Command, args []string) error {
//	    cmdCtx := GetCommandContext(cmd)
//	    if cmdCtx == nil {
//	        return errors.New("command context not initialized")
//	    }
//	    cmdCtx.Logger.Info("running command")
//	    // use cmdCtx.Config, cmdCtx.Logger
//	}
func GetCommandContext(cmd *cobra.Command) *CommandContext {
	if cmd == nil {
		return nil
	}
	ctx := cmd.Context()
	if ctx == nil {
		return nil
	}
	cmdCtx, ok := ctx.Value(cmdContextKey).(*CommandContext)
	if !ok {
		return nil
	}
	return cmdCtx
}

// SetCommandContext stores the CommandContext in the command's context.
// If the command's context is nil, a new background context is created.
//
// This should be called in PersistentPreRunE of the root command to make
// the context available to all subcommands.
func SetCommandContext(cmd *cobra.Command, cmdCtx *CommandContext) {
	if cmd == nil {
		return
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = context.WithValue(ctx, cmdContextKey, cmdCtx)
	cmd.SetContext(ctx)
}
