// Command aws-sso-profile-sync is the canonical go-install entry point.
// Flags and signals are delegated to the reusable CLI coordinator.
package main

import (
	"context"
	"github.com/LanceSandino/aws-sso-profile-sync/v2/internal/cli"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
