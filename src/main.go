package higgs

func Run(configPath string) {
	c := loadConfig(configPath)
	s := (&server{config: *c}).init()
	s.run()
}
