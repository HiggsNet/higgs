package main

import (
	"flag"

	configserver "github.com/Catofes/higgs/src/ConfigServer"
)

func main() {
	listen := flag.String("l", "[::]:8008", "Listen Address")
	config := flag.String("c", ".", "config path")
	flag.Parse()
	web := configserver.Web{
		Config: configserver.Config{
			Listen:   *listen,
			RootPath: *config,
		},
	}
	web.Run()
}
