package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/hashicorp/vault/shamir"
)

func (e *encryptionData) shamirSplit() error {
	shamirBytes, err := shamir.Split(e.RecoveryKey, e.RecoveryConfig.SecretShares, e.RecoveryConfig.SecretThreshold)
	if err != nil {
		log.Fatalf("failed to create Shamir key shares of recovery key: %v", err)
	}

	for idx, keyshare := range shamirBytes {
		fmt.Printf("recovery key share %v: %s\n", idx+1, base64.StdEncoding.EncodeToString(keyshare))
	}

	return nil
}

func inputKeyShares(e *encryptionData) ([]byte, error) {
	inputString := make([]string, e.ShamirConfig.SecretThreshold)
	inputBytes := make([][]byte, e.ShamirConfig.SecretThreshold)

	for idx := range inputString {
		fmt.Printf("unseal key share (%d of %d): ", idx+1, e.ShamirConfig.SecretThreshold)
		fmt.Scanln(&inputString[idx])
		bytes, _ := base64.StdEncoding.DecodeString(inputString[idx])
		inputBytes[idx] = bytes
	}

	combineOutput, err := shamir.Combine(inputBytes)
	if err != nil {
		return nil, fmt.Errorf("error combining input strings: %v", err)
	}
	return combineOutput, nil
}
