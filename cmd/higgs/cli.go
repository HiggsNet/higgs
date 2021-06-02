package main

import (
	higgs "github.com/HiggsNet/higgs/src"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

var h *higgs.Higgs

var commonFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "config",
		Usage:   "path to configuration file",
		Aliases: []string{"c"},
		Value:   "/etc/higgs/higgs.conf",
	},
	&cli.BoolFlag{
		Name:    "debug",
		Usage:   "enable debug log",
		Aliases: []string{"d"},
		Value:   false,
	},
}

var commonBeforeFunc = func(ctx *cli.Context) error {
	logConfig := zap.NewDevelopmentConfig()
	logConfig.DisableStacktrace = true
	switch ctx.Bool("debug") {
	case true:
		logConfig.Level.SetLevel(zap.DebugLevel)
	case false:
		logConfig.Level.SetLevel(zap.InfoLevel)
	}

	logger, err := logConfig.Build()
	if err != nil {
		return err
	}
	zap.ReplaceGlobals(logger)

	h = (&higgs.Higgs{}).LoadConf(ctx.String("config"))
	return nil
}

func getApp() *cli.App {
	return &cli.App{
		Name:      "higgs",
		Usage:     "Higgs network manager.",
		UsageText: "higgs [command] [option]",
		Version:   Version,
		Commands: []*cli.Command{
			{
				Name:      "push",
				Aliases:   []string{"p"},
				Usage:     "push metadata",
				UsageText: "higgs push [options] DEST",
				Flags:     commonFlags,
				Before:    commonBeforeFunc,
				Action: func(ctx *cli.Context) error {
					return h.PushMetadata()
				},
			},
		},
	}
}
