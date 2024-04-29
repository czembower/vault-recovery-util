# vault-recovery-util

This tool reads and decrypt data from Vault's BoltDB storage backend, given
sufficient access to the auto-unseal device or a reconstructed unseal key. It
can also be used to generate new recovery/unseal key shares and inspect the
keyring.

Note that extremely sensitive data can be exposed through the use of this
utility. It should only be used for educational or emergency applications.

```shell
Usage of vault-recovery-util:
  -genRecoveryKeyShares
        Set to true to generate new recovery key shares
  -printKeyring
        Display the keyring data, including the data encryption keys and root key in base64 format
  -printRecoveryKey
        Display the recovery key in base64 format
  -printSealConfig
        Display the seal configuration
  -printUnsealKey
        Display the unseal key in base64 format
  -readPath string
        BoltDB path to key that should be decrypted and returning in plain text
  -vaultConfig string
        Path to the Vault server configuration file (default "./vault.hcl")
```
