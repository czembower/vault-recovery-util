# vault-recovery-util

This tool reads and decrypts data from Vault's BoltDB storage backend, given
sufficient access to the auto-unseal device or a reconstructed Shamir unseal
key. It can also be used to generate new recovery/unseal key shares and inspect
the keyring.

Note that extremely sensitive data can be exposed through the use of this
utility. It should only be used for educational or emergency applications.

```shell
Usage of vault-recovery-util:
  -deleteKey string
        BoltDB path to key that should be deleted
  -genKeyShares
        Set to true to generate new recovery/unseal key shares, depending on the seal type
  -listDb
        Display the BoltDB database contents
  -printKeys
        Display recovery/unseal key and the keyring data, including the data encryption keys and root key in base64 format
  -printSealConfig
        Display the seal configuration
  -readKey string
        BoltDB path to key that should be decrypted and returned in plain text - if decryption fails, raw DB data will be displayed instead
  -sealWrap
        Set to false to disable seal wrap logic - this is necessary for Vault community edition or if seal wrap is explicitly disabled in Vault Enterprise (default true)
  -vaultConfig string
        Path to the Vault server configuration file (default "./vault.hcl")
```
