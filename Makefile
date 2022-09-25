all:
	mkdir -p build
	env CGO_BUILD=0 go build -o build/ConfigServer ./app/ConfigServer