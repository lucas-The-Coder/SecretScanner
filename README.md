# SecretScanner Mini

Scan a text file for leaked secrets. Backend only, Node.js CLI.

Finds 【entity-AWS¦canonical_name=AWS】 keys, GitHub tokens, private keys, generic API keys, and high entropy strings, then saves findings to `secrets.json`.

## Features

- Regex patterns for 【entity-AWS¦canonical_name=AWS】, 【entity-GitHub¦canonical_name=GitHub】, private keys, and generic API keys
- Shannon entropy check for random high entropy tokens
- Line number for every finding
- Findings saved as JSON for SOC triage
- Clean handling for missing file, no crash, no fake CLEAN
- No printing inside helpers, only `main()` prints

## Project Structure

- `secret_scanner.js` - Main scanner
- `sample_secrets.txt` - Fake test file, no real secrets
- `secrets.json` - Generated output, gitignored

## How to Run

No dependencies. Node.js only.

```bash
node secret_scanner.js
node secret_scanner.js sample_secrets.txt
node secret_scanner.js missing.txt
