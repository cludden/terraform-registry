package main

import (
	"github.com/alecthomas/kong"
	"github.com/cludden/terraform-registry/cmd"
)

func main() {
	ctx := kong.Parse(&cmd.CLI)
	ctx.FatalIfErrorf(ctx.Run())
}
