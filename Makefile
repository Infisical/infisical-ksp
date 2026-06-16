# Infisical KSP - build and test
#
# The OS-agnostic packages (internal/infisical, internal/cng) build and test on any
# platform. The KSP DLL itself is cgo + Windows-only and is built on Windows (or with a
# mingw-w64 cross toolchain plus the Windows SDK / CPDK headers). See the README.

BUILD_DIR    := build
DLL_NAME     := infisical-ksp.dll
DLL_NAME_X86 := infisical-ksp-x86.dll

.PHONY: test vet tidy lint build-windows build-windows-x86 clean

## test: run unit tests for the OS-agnostic packages (works on macOS/Linux/Windows)
test:
	go test ./...

## vet: static analysis of the OS-agnostic packages
vet:
	go vet ./...

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## build-windows: build the 64-bit KSP DLL. Run on Windows (CGO + Windows SDK / CPDK).
## On Windows PowerShell, the equivalent is:
##   $env:CGO_ENABLED=1; go build -buildmode=c-shared -o build/infisical-ksp.dll ./cmd/ksp
build-windows:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
		go build -buildmode=c-shared -o $(BUILD_DIR)/$(DLL_NAME) ./cmd/ksp

build-windows-x86:
	CGO_ENABLED=1 GOOS=windows GOARCH=386 \
		go build -buildmode=c-shared -ldflags="-extldflags=-Wl,--kill-at" -o $(BUILD_DIR)/$(DLL_NAME_X86) ./cmd/ksp

clean:
	rm -rf $(BUILD_DIR)
