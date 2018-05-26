package main

import (
	"fmt"
	"os"

	"istio.io/istio/security/pkg/nodeagentpoc"

	"github.com/spf13/cobra"
	"istio.io/istio/pkg/cmd"
	"istio.io/istio/pkg/log"
)

var (
	serverArgs nodeagent.NodeAgentArgs

	loggingOptions = log.DefaultOptions()

	rootCmd = &cobra.Command{
		Use:   "node-agent",
		Short: "Node Agent",
		Long:  "",
	}

	agentCmd = &cobra.Command{
		Use:   "agent",
		Short: "Start node agent service",
		RunE: func(c *cobra.Command, args []string) error {
			if err := log.Configure(loggingOptions); err != nil {
				return err
			}

			// Create the stop channel for all of the servers.
			stop := make(chan struct{})

			// Create the server for the discovery service.
			_, err := nodeagent.NewServer(serverArgs)
			if err != nil {
				return fmt.Errorf("failed to create node agent: %v", err)
			}

			cmd.WaitSignal(stop)
			return nil
		},
	}
)

func init() {
	agentCmd.PersistentFlags().StringVar(&serverArgs.SDSUdsSocket, "sdsUdsSocket", "/tmp/gotest4.sock", "")
	rootCmd.AddCommand(agentCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(-1)
	}
}
