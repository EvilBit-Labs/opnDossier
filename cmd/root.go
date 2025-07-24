// Package cmd provides the command-line interface for opnFocus.
/*
Copyright © 2024 UncleSp1d3r <unclespider@protonmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"

	goutbra "github.com/drewstinnett/gout-cobra"
	"github.com/drewstinnett/gout/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "opnFocus",
	Short: "Generate meaningful output from your opnSense configuration files.",
	Long: `opnFocus is a tool to generate meaningful output from your opnSense configuration files. 
It is designed to be used in a pipeline with other tools to generate reports, 
or to be used as a standalone tool to generate human-readable output from your opnSense configuration files.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(_ *cobra.Command, args []string) {
		dat, err := os.Open(args[0])
		if err != nil {
			log.Fatal(err)
		}
		dec := xml.NewDecoder(dat)
		var doc Opnsense
		if err := dec.Decode(&doc); err != nil {
			log.Fatal(err)
		}
		gout.MustPrint(doc)
	},
	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		err := goutbra.Cmd(cmd)
		if err != nil {
			log.Fatal(err)
		}
	},
	Args: cobra.ExactArgs(1),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.opnFocus.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	err := goutbra.Bind(rootCmd, goutbra.WithHelp("Some help"))
	if err != nil {
		return
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".opnFocus" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".opnFocus")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
