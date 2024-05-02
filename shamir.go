package main

import (
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/shamir"
)

func (e *encryptionData) shamirSplit() error {
	var shamirBytes [][]byte
	var recovery bool
	var shamirType string
	var err error

	if e.RecoveryKey == nil {
		recovery = false
		shamirType = "unseal"
	} else {
		recovery = true
		shamirType = "recovery"
	}

	if recovery {
		shamirBytes, err = shamir.Split(e.RecoveryKey, e.RecoveryConfig.SecretShares, e.RecoveryConfig.SecretThreshold)
	} else {
		shamirBytes, err = shamir.Split(e.UnsealKey, e.ShamirConfig.SecretShares, e.ShamirConfig.SecretThreshold)
	}
	if err != nil {
		return fmt.Errorf("failed to create Shamir key shares of %s key: %v", shamirType, err)
	}

	for idx, keyshare := range shamirBytes {
		fmt.Printf("%s key share %v: %s\n", shamirType, idx+1, base64.StdEncoding.EncodeToString(keyshare))
	}

	return nil
}

func inputKeyShares(s shamirOrRecoveryConfig) ([]byte, error) {
	inputString := make([]string, s.SecretThreshold)
	inputBytes := make([][]byte, s.SecretThreshold)

	for idx := range inputString {
		fmt.Printf("unseal key share (%d of %d)", idx+1, s.SecretThreshold)
		inputString[idx] = getPassword(": ")
		bytes, _ := base64.StdEncoding.DecodeString(inputString[idx])
		inputBytes[idx] = bytes
	}

	combineOutput, err := shamir.Combine(inputBytes)
	if err != nil {
		return nil, fmt.Errorf("error combining input strings: %v", err)
	}
	return combineOutput, nil
}
