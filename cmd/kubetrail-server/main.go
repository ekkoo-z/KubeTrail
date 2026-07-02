package main

import (
	"os"

	"github.com/ekkoo-z/KubeTrail/internal/command"
)

func main() {
	os.Exit(command.Run(os.Args, os.Stdout, os.Stderr))
}
