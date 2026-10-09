# Azure Local Build Scripts

Scripts for building the attestation SDK (Clientlib), SKR sample app, and attestation client sample app for Azure Local.

## Projects

- [Attestation Client Sample App](../cvm-attestation-sample-app/README.md)
- [Secure Key Release Sample App](../cvm-securekey-release-app/README.md)
- Attestation Client Library (`../client-library/`)

## Build

```bash
./build-azure-local.sh        # Build and gather artifacts
./build-azure-local.sh -c     # Clean rebuild
./build-azure-local.sh -p     # Install pre-requisites first
./build-azure-local.sh -cp    # Clean rebuild with pre-requisites
./build-azure-local.sh -cpi   # Clean rebuild with the insiders-fast evidence SDK
```

On Ubuntu 22.04 and 24.04, pre-requisite installation configures and validates the
Microsoft production `prod.list` feed and installs `edge-cc-base-attestation-sdk`
from the matching Ubuntu release. Use `-i` together with `-p` to explicitly opt
into insiders-fast instead. The selected SDK feed is honored even when both feeds
are configured; switching back to production can downgrade an installed preview SDK.
Other configured feeds are left intact.

Artifacts are collected into the `output/` directory at the repo root.
