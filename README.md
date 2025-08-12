## Overview
**WAY_EXTRACTOR** is a global secret, API key, and URL extractor built for bug bounty hunters and red teamers 
It hunts down:
- API keys (AWS, Google, GitHub, Stripe, Slack, etc.)
- Database credentials (MySQL, PostgreSQL, MongoDB, Cloudinary, etc.)
- OAuth tokens, JWTs, and private keys
- URLs (generic + with extensions like `.js`, `.sql`, `.env`, etc.)
- High-entropy strings likely to be secrets

The tool recursively scans files or entire directories, applying targeted regex signatures and entropy analysis.

---

## Requirements
- **Python 3.8+**
- Runs on Linux, macOS, or Windows.
- No external dependencies.

---

## Installation
Clone the repo and make the script executable:

```bash
git clone https://github.com/yourusername/way_extractor.git
cd way_extractor
chmod +x way_extractor.py
