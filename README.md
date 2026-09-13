# Timestamping Service (TSS)
A secure, standards-compliant Time Stamping Authority (TSA) client-server implementation in C++ and OpenSSL for the Foundations of Cybersecurity course.

## Key Features
- **Strict Key Separation:** Ephemeral TLS 1.3 connection keys (`P-256`) decoupled from long-term timestamp signing keys (`P-384 / SHA-384`).
- **Data Minimization:** Documents never leave the client; only streaming SHA-256 digests are transmitted.
- **Perfect Forward Secrecy (PFS):** Guaranteed via strictly mandated TLS 1.3 ECDHE cipher suites (`TLS_AES_256_GCM_SHA384`).
- **Multi-Layer Replay Protection:** In-session monotonically increasing sequence numbers (`seq`) and cryptographic nonce (`nonce_s`).
- **Offline Verifier (`tss_verify`):** Standalone zero-network CLI tool to verify token integrity and assert physical document binding.

## Quick Start

### 1. Generate Certificates and Demo Users
```bash
./keygen.sh
```

### 2. Build the Project
```bash
./build.sh
```

### 3. Run the Server
```bash
./build/tss_server
```

### 4. Run the Interactive Client
```bash
./build/tss_client --user alice --pass alice_password
```

### 5. Verify a Token Offline
```bash
./build/tss_verify --token token_<hash>.json --file documento.txt
```

## Protocol Diagrams
Detailed sequence diagrams and protocol flows are available in the [`figures/`](figures/) directory.
