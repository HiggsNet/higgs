package main

import (
	"fmt"
	"os"

	higgs "github.com/Catofes/higgs/src"
	cli "github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var commonFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "config",
		Usage:   "path to configuration file",
		Aliases: []string{"c"},
		Value:   "/etc/rait/rait.conf",
	},
	&cli.BoolFlag{
		Name:    "debug",
		Usage:   "enable debug log",
		Aliases: []string{"d"},
		Value:   false,
	},
}

var signFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "config",
		Usage:   "path to configuration file",
		Aliases: []string{"c"},
		Value:   "/etc/rait/rait.conf",
	},
	&cli.StringFlag{
		Name:    "domain",
		Usage:   "domain",
		Aliases: []string{"d"},
		Value:   "example.",
	},
	&cli.StringFlag{
		Name:    "key",
		Usage:   "public key",
		Aliases: []string{"k"},
		Value:   "/etc/rait/rait.conf",
	},
}

var h *higgs.Higgs
var Version string

var commonBeforeFunc = func(ctx *cli.Context) error {
	h = &higgs.Higgs{}
	return nil
}

func main() {
	app := &cli.App{
		Name:      "higgs",
		Usage:     "Higgs Net Manager",
		UsageText: "higgs [command] [options]",
		Version:   Version,
		Commands: []*cli.Command{
			{
				Name:      "genkey",
				Usage:     "generate private and public key",
				UsageText: "higgs genkey",
				Action: func(ctx *cli.Context) error {
					fmt.Print(higgs.GenerateKey())
					return nil
				},
			}, {
				Name:      "getid",
				Usage:     "get p2pid from config file",
				UsageText: "higgs -c ./higgs.hcl getid",
				Flags:     commonFlags,
				Before:    commonBeforeFunc,
				Action: func(ctx *cli.Context) error {
					h.GetID(ctx.String("config"))
					return nil
				},
			}, {
				Name:      "sign",
				Usage:     "run daemon",
				UsageText: "higgs -c ./higgs.hcl run",
				Flags:     signFlags,
				Before:    commonBeforeFunc,
				Action: func(ctx *cli.Context) error {
					h.Sign(ctx.String("config"), ctx.String("domain"), ctx.String("key"))
					return nil
				},
			}, {
				Name:      "run",
				Usage:     "run daemon",
				UsageText: "higgs -c ./higgs.hcl run",
				Flags:     commonFlags,
				Before:    commonBeforeFunc,
				Action: func(ctx *cli.Context) error {
					h.Run(ctx.String("config"))
					return nil
				},
			},
		}}
	if err := app.Run(os.Args); err != nil {
		zap.S().Error(err)
		os.Exit(1)
	}
}
