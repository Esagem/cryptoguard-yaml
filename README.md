# CryptoGuard YAML

CryptoGuard YAML is a lightweight static checker that scans **YAML-formatted security/requirements user stories** and flags violations of the IEEE design principle: **Use cryptography correctly**.

This project is designed to catch crypto mistakes early—at the *requirements stage*—before they become implementation defects.

## What it detects

CryptoGuard YAML identifies potential issues related to:

- **Do not use your own cryptographic algorithms/implementations**
- **Misuse of libraries and algorithms** (e.g., MD5 for passwords)
- **Poor key management** (e.g., “protecting” API keys by hashing instead of using a secret manager)
- **Randomness that is not random** (fixed ranges, fixed seeds, low entropy)
- **Algorithm agility** (ability to evolve to stronger algorithms over time — reported as a *note* when done well)

## Example input (YAML)

```yaml
- ALL: "This user story focuses on crypto-related requirements"
  R1: "We will use MD5 for encrypting all passwords and GitHub API keys."
  R2: "For generating random numbers we will use a fixed range between 1 and 151."
  R3: "We will be using our own implementation of SHA512 to protect API keys used for GPT-o4."
  R4: "Keys for vault will be rotated."
  R5: "If a new cryptography algorithm comes with better strength, then we will use it instead of SHA512."
