all:
	mkdir -p build
	env CGO_ENABLED=0 go build -o build/app ./app/higgs
