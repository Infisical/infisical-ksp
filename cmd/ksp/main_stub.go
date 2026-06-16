//go:build !windows

// The Infisical KSP is a Windows-only CNG Key Storage Provider. This stub lets the module
// build, `go vet`, and `go test` on non-Windows hosts. The DLL is produced on Windows with
// cgo; see bridge_windows.go.
package main

func main() {}
