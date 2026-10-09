# Detection Rules (Detection-as-Code)

This repository contains production-ready detection rules mapped to the MITRE ATT&CK framework. It implements a Detection-as-Code (DaC) pipeline utilizing GitHub Actions to continuously test and validate signatures.

## Repository Structure

- `sigma/`: Generic log signatures for SIEMs (Windows, Linux).
- `yara/`: Malware and file-based signatures.
- `.github/workflows/`: CI/CD pipelines for validation.

## Continuous Integration (CI/CD)
Every pull request and push to the `main` branch triggers automated linting:
1. **Sigma Validation**: Validates rule syntax and schema using `sigma-cli`.
2. **YARA Compilation**: Compiles and syntax-checks rules using the standard `yara` compiler.
