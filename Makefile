build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Version=`git describe --tags`" -o bin/higgs github.com/HiggsNet/higgs/cmd/higgs
clean:
	rm -r bin/
.PHONY: build
