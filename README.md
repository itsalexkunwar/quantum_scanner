# Cryptography Inventory and Quantum Readiness Scanner

Deterministic static analysis for cryptographic inventory and quantum readiness assessment.

A Python command line tool that statically analyzes source code to inventory cryptographic usage and highlight quantum vulnerable and obsolete algorithms.

## Overview

Organizations cannot modernize cryptography without first understanding where and how it is used. Post quantum transition begins with visibility.

The Cryptography Inventory and Quantum Readiness Scanner performs static AST based analysis of Python source code to identify cryptographic usage patterns, broken algorithms, obsolete TLS versions, and quantum vulnerable primitives.

The tool produces deterministic, stable, and machine readable output suitable for automation and compliance workflows.

## Features

* AST based static analysis
* Detects cryptography related imports
* Flags broken hash algorithms such as MD5 and SHA1
* Flags obsolete TLS 1.0 and TLS 1.1 usage
* Flags quantum vulnerable algorithms such as RSA and EC
* Deterministic sorted output
* Stable JSON schema version 1.0
* Output equivalence tested
* Controlled fixtures for repeatable testing

## Quick Start

Clone the repository:

git clone https://github.com/itsalexkunwar/quantum_scanner.git
cd quantum_scanner

Create a virtual environment and activate it:

python -m venv venv
source venv/bin/activate

Run a scan:

python qscan.py path_to_scan

Run in JSON mode:

python qscan.py path_to_scan --json

Adjust the JSON flag if your CLI uses a different option.

## Supported Scope

### In Scope

* Python source files with .py extension
* Static AST analysis of source code
* Detection rules defined within the scanner
* Deterministic human readable output
* Stable JSON schema version 1.0

### Out of Scope

* Other programming languages
* Runtime network inspection
* Binary artifact analysis
* Dynamic execution tracing
* Live TLS negotiation validation

## Detection Level

This tool performs deterministic static analysis using the Python AST module.

Direct imports, attribute references, and explicit usage patterns defined in the rule set are detected reliably.

Dynamic imports, reflection, runtime constructed calls, and execution through eval or similar mechanisms may not be detected.

Findings should be treated as indicators for review rather than proof of exploitability.

## Known Limitations

* Only Python source code is supported
* Static analysis only, no runtime validation
* May miss dynamically constructed cryptographic calls
* May report findings in unreachable or test code
* Does not verify actual negotiated TLS versions at runtime

## Example Output

### Human Output

Cryptography Inventory and Quantum Readiness Scanner
Target: /Users/Quantum/mvp/ms_0
Python files scanned: 1
Findings: 6

Summary
  Broken: 1
  Obsolete TLS: 1
  Quantum vulnerable: 1
  Imports: 3

Exit code: 1

Findings

/Users/Quantum/mvp/ms_0/sample.py
  L1  import  hashlib  Imports cryptography related module.
  L2  import  ssl  Imports cryptography related module.
  L3  import  cryptography.hazmat.primitives.asymmetric.rsa  Imports cryptography related symbol.
  L6  broken  hashlib.md5  MD5 is broken and should not be used for security purposes.
  L9  obsolete_tls  ssl.PROTOCOL_TLSv1  TLS 1.0 is obsolete and should not be used.
  L13  quantum_vulnerable  cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key  RSA is vulnerable to future quantum attacks. Plan migration to PQC.

### JSON Output

{
  "schema_version": "1.0",
  "summary": {
    "files_scanned": 1,
    "findings": 6,
    "broken": 1,
    "obsolete_tls": 1,
    "quantum_vulnerable": 1,
    "imports": 3
  },
  "findings": [
    {
      "category": "import",
      "file_path": "/Users/Quantum/mvp/ms_0/sample.py",
      "line_number": 1,
      "match": "hashlib",
      "message": "Imports cryptography related module."
    },
    {
      "category": "import",
      "file_path": "/Users/Quantum/mvp/ms_0/sample.py",
      "line_number": 2,
      "match": "ssl",
      "message": "Imports cryptography related module."
    },
    {
      "category": "import",
      "file_path": "/Users/Quantum/mvp/ms_0/sample.py",
      "line_number": 3,
      "match": "cryptography.hazmat.primitives.asymmetric.rsa",
      "message": "Imports cryptography related symbol."
    },
    {
      "category": "broken",
      "file_path": "/Users/Quantum/mvp/ms_0/sample.py",
      "line_number": 6,
      "match": "hashlib.md5",
      "message": "MD5 is broken and should not be used for security purposes."
    },
    {
      "category": "obsolete_tls",
      "file_path": "/Users/Quantum/mvp/ms_0/sample.py",
      "line_number": 9,
      "match": "ssl.PROTOCOL_TLSv1",
      "message": "TLS 1.0 is obsolete and should not be used."
    },
    {
      "category": "quantum_vulnerable",
      "file_path": "/Users/Quantum/mvp/ms_0/sample.py",
      "line_number": 13,
      "match": "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
      "message": "RSA is vulnerable to future quantum attacks. Plan migration to PQC."
    }
  ]
}

## License

This project is licensed under the MIT License. See the LICENSE file for details.