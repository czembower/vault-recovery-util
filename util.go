package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/vault/sdk/helper/compressutil"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"google.golang.org/protobuf/proto"
)

type VaultDataTable struct {
	Type    string        `json:"type"`
	Entries []interface{} `json:"entries"`
}

func protoUnmarshal(data []byte) (*wrapping.BlobInfo, error) {
	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(data, blobInfo); err != nil {
		eLen := len(data)
		if err := proto.Unmarshal(data[:eLen-1], blobInfo); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ciphertext to blob: %s: %v", err, blobInfo)
		}
	}
	return blobInfo, nil
}

func copyFile(source string, dest string) error {
	input, err := os.ReadFile(source)
	if err != nil {
		return err
	}

	err = os.WriteFile(dest, input, 0644)
	if err != nil {
		return err
	}
	return nil
}

func isASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}

	return true
}

func termEcho(on bool) {
	attrs := syscall.ProcAttr{
		Dir:   "",
		Env:   []string{},
		Files: []uintptr{os.Stdin.Fd(), os.Stdout.Fd(), os.Stderr.Fd()},
		Sys:   nil}
	var ws syscall.WaitStatus
	cmd := "echo"
	if !on {
		cmd = "-echo"
	}

	pid, err := syscall.ForkExec(
		"/bin/stty",
		[]string{"stty", cmd},
		&attrs)
	if err != nil {
		panic(err)
	}

	_, err = syscall.Wait4(pid, &ws, 0, nil)
	if err != nil {
		panic(err)
	}
}

func getPassword(prompt string) string {
	fmt.Print(prompt)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func() {
		for _ = range signalChannel {
			fmt.Println("\n^C interrupt.")
			termEcho(true)
			os.Exit(1)
		}
	}()

	termEcho(false)
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	termEcho(true)
	fmt.Println("")
	if err != nil {
		fmt.Println("ERROR:", err.Error())
		os.Exit(1)
	}
	return strings.TrimSpace(text)
}

func checkCompressed(input []byte) ([]byte, error) {
	vaultDataTable := &VaultDataTable{}
	var bytes []byte

	// Check to see if the returned data is compressed or not
	_, uncompressed, _ := compressutil.Decompress(input)
	// If the data is compressed, pass it through jsonutil and return the result
	if !uncompressed {
		err := jsonutil.DecodeJSON(input, vaultDataTable)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress result: %v", err)
		}
		bytes, err = json.Marshal(vaultDataTable)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal decompressed data: %v", err)
		}
		return bytes, nil
	}
	// if it is not compressed, return an empty result and error
	return nil, fmt.Errorf("data not compressed")
}

func checkPem(input []byte) ([]byte, error) {
	// Check to see if the returned data is an X.509 certificate
	// If it is, return PEM for convenience
	cert, err := x509.ParseCertificate(input)
	if err != nil {
		return nil, fmt.Errorf("input is not PEM data")
	}

	publicKeyBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	certPem := string(pem.EncodeToMemory(&publicKeyBlock))
	return []byte(certPem), nil
}
