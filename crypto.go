package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
	"github.com/hashicorp/vault/sdk/helper/compressutil"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"google.golang.org/protobuf/proto"
)

// decryptSeal uses the auto-unseal device or unseal key to decrypt the provided ciphertext
func (e *encryptionData) decryptSeal(ciphertext []byte) ([]byte, error) {
	ctx := context.Background()

	// Load the ciphertext into a blobInfo object
	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(ciphertext, blobInfo); err != nil {
		eLen := len(ciphertext)
		if err := proto.Unmarshal(ciphertext[:eLen-1], blobInfo); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ciphertext to blob: %s: %v", err, blobInfo)
		}
	}

	// Set wrapper configuration based on seal type and decrypt
	// SetConfig uses the following precendence to discover these values:
	// 1. environment variables
	// 2. configuration file
	// 3. instance identity/credentials
	var pt []byte
	switch e.SealConfig.Type {
	case "transit":
		wrapper := transit.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"mount_path":      e.SealConfig.TransitConfig.MountPath,
			"key_name":        e.SealConfig.TransitConfig.KeyName,
			"address":         e.SealConfig.TransitConfig.Address,
			"token":           e.SealConfig.TransitConfig.Token,
			"namespace":       e.SealConfig.TransitConfig.Namespace,
			"tls_ca_cert":     e.SealConfig.TransitConfig.TlsCaCert,
			"tls_skip_verify": strconv.FormatBool(e.SealConfig.TransitConfig.TlsSkipVerify),
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "gcpckms":
		wrapper := gcpckms.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"user_agent":  e.SealConfig.GcpCkmsConfig.UserAgent,
			"credentials": e.SealConfig.GcpCkmsConfig.Credentials,
			"project":     e.SealConfig.GcpCkmsConfig.Project,
			"region":      e.SealConfig.GcpCkmsConfig.Region,
			"key_ring":    e.SealConfig.GcpCkmsConfig.KeyRing,
			"crypto_key":  e.SealConfig.GcpCkmsConfig.CryptoKey,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "azurekeyvault":
		wrapper := azurekeyvault.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"tenant_id":     e.SealConfig.AzureKeyVaultConfig.TenantID,
			"client_id":     e.SealConfig.AzureKeyVaultConfig.ClientID,
			"client_secret": e.SealConfig.AzureKeyVaultConfig.ClientSecret,
			"resource":      e.SealConfig.AzureKeyVaultConfig.Resource,
			"vault_name":    e.SealConfig.AzureKeyVaultConfig.VaultName,
			"key_name":      e.SealConfig.AzureKeyVaultConfig.KeyName,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "awskms":
		wrapper := awskms.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithKeyId(""), wrapping.WithConfigMap(map[string]string{
			"region":                  e.SealConfig.AwsKmsConfig.Region,
			"endpoint":                e.SealConfig.AwsKmsConfig.Endpoint,
			"access_key":              e.SealConfig.AwsKmsConfig.AccessKey,
			"secret_key":              e.SealConfig.AwsKmsConfig.SecretKey,
			"session_token":           e.SealConfig.AwsKmsConfig.SessionToken,
			"shared_creds_filename":   e.SealConfig.AwsKmsConfig.SharedCredsFile,
			"shared_creds_profile":    e.SealConfig.AwsKmsConfig.SharedCredsProfile,
			"web_identity_token_file": e.SealConfig.AwsKmsConfig.WebIdentityTokenFile,
			"role_session_name":       e.SealConfig.AwsKmsConfig.RoleSessionName,
			"role_arn":                e.SealConfig.AwsKmsConfig.RoleArn,
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	case "shamir":
		if e.UnsealKey == nil {
			fmt.Printf("no unseal key found, collecting key shares from input (threshold: %d)\n", e.ShamirConfig.SecretThreshold)
			combinedUnsealKey, err := inputKeyShares(e.ShamirConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to combine key shares: %s: %v", err, blobInfo)
			}
			e.UnsealKey = combinedUnsealKey
		}
		wrapper := aead.NewWrapper()
		_, err := wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
			"key": base64.StdEncoding.EncodeToString(e.UnsealKey),
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to initialize wrapper: %s", err)
		}
		pt, err = wrapper.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt blobInfo: %s: %v", err, blobInfo)
		}
	default:
		return nil, fmt.Errorf("seal type not supported")
	}

	return pt, nil
}

// decrypt uses the provided key to open the ciphertext using AES-GCM
func decrypt(ciphertext []byte, key []byte, aadPath string) ([]byte, error) {
	// Load the key into an AES cipher
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Create the GCM from the cipher block
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	sz := gcm.NonceSize()
	if len(ciphertext) < sz {
		return nil, fmt.Errorf("invalid ciphertext length")
	}

	// Parse ciphertext for nonce and secret contents,
	// exluding the key term (4) and version (+1=5)
	nonce, raw := ciphertext[5:5+sz], ciphertext[5+sz:]
	out := make([]byte, 0, len(raw)-sz)

	// Open and decrypt
	var result []byte
	switch ciphertext[4] {
	case AESGCMVersion1:
		result, err = gcm.Open(out, nonce, raw, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt AESGCMVersion1 ciphertext: %v", err)
		}
	// Version2 uses the data path as additional authentication data
	case AESGCMVersion2:
		aad := []byte(nil)
		if aadPath != "" {
			aad = []byte(aadPath)
		}
		result, err = gcm.Open(out, nonce, raw, aad)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt AESGCMVersion2 ciphertext: %v", err)
		}
	default:
		return nil, fmt.Errorf("version bytes mis-match")
	}

	// Check to see if the returned data is compressed or not
	_, uncompressed, _ := compressutil.Decompress(result)
	if aadPath != keyringPath {
		fmt.Printf("compressed: %t\n", !uncompressed)
	}
	// If the data is compressed, pass it through jsonutil
	if !uncompressed {
		type VaultDataTable struct {
			Type    string        `json:"type"`
			Entries []interface{} `json:"entries"`
		}

		vaultDataTable := &VaultDataTable{}
		err := jsonutil.DecodeJSON(result, vaultDataTable)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress result: %v", err)
		}
		fmt.Printf("decrypted content:\n%s\n", vaultDataTable)
		return nil, nil
	}

	// Check to see if the returned data is an X.509 certificate
	// If it is, return PEM for convenience
	cert, err := x509.ParseCertificate(result)
	if err == nil {
		publicKeyBlock := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		certPem := string(pem.EncodeToMemory(&publicKeyBlock))
		fmt.Printf("decrypted content:\n%s\n", certPem)
		return nil, nil
	}

	return result, nil
}
