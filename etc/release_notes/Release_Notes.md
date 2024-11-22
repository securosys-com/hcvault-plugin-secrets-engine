# Securosys Hashicorp Vault Secrets Engine 1.2.6
Issued: Nov, 22, 2024
## Feature
- Added integration tests
- Added new types of keys names = aes128-gcm96, chacha20-poly1305, ed25519

# Securosys Hashicorp Vault Secrets Engine 1.2.5
Issued: Nov, 14, 2024
## Bugfix
- Fixed error on export imported key pair, when extractable=true and sensitive=false
- Remove keys, that not exists on HSM.
## Feature
- Added on key listing information about CurveOid for EC and ED keys
- Added new endpoint to list all keys in HSM

# Securosys Hashicorp Vault Secrets Engine 1.2.4
Issued: Sep, 25, 2024
## Bugfix
- Fixed error on using key with changed policy not by Secrets Engine

# Securosys Hashicorp Vault Secrets Engine 1.2.3
Issued: Sep, 20, 2024
## Bugfix
- Fixed listing approvers on requests

# Securosys Hashicorp Vault Secrets Engine 1.2.2
Issued: Sep, 3, 2024
## Feature
- Added support for additional MetaData to asynchronous requests like sign, decrypt, unwrap, modify, block and unblock
## Documentation Change
- Update Readme.md - added information about additional MetaData

# Securosys Hashicorp Vault Secrets Engine 1.2.1
Issued: Aug, 30, 2024
## Feature
- Added support for new TSB Policy type - onboarded_approver_certificate

# Securosys Hashicorp Vault Secrets Engine 1.2.0
Issued: Aug, 27, 2024
## Feature
- Added support for TSB Api Keys

# Securosys Hashicorp Vault Secrets Engine 1.1.0
Issued: Dec, 6, 2023
## Documentation Change
- Update Readme.md - added information about supporting and how to configure encryption on MariaDB
## Feature
- Added integration with MariaDB encryption
## Bugfix
- Fixed authentication with TSB using mTLS

# Securosys Hashicorp Vault Secrets Engine 1.0.3
Issued: Nov, 28, 2023
## Documentation Change
- Update Readme.md - added CGO_ENABLED=0 in build command
## Bugfix
- Added CGO_ENABLED=0 to every build/

# Securosys Hashicorp Vault Secrets Engine 1.0.2
Issued: Nov, 6, 2023
## Documentation Change
- Update Readme.md
- Added License.txt

# Securosys Hashicorp Vault Secrets Engine 1.0.1
Issued: Sep, 18, 2023
## Bugfix
- Removed sending empty password char array on not provided password.

# Securosys Hashicorp Vault Secrets Engine 1.0.0
Issued: May, 26, 2024