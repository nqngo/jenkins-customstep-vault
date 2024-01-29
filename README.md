# Vault Custom Step for Jenkins
A customStep to abstract the logic of accessing Hashicorp Vault in Jenkins pipeline. At the moment, it supports the following methods:

- `getVaultSecret`: fetch a KV v2 secret from Hashicorp Vault.

## Reference
- https://www.jenkins.io/doc/book/pipeline/shared-libraries/#defining-custom-steps
