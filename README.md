# Secure and Tamper-Resistant Blockchain Electronic Voting System

[![Language](https://img.shields.io/badge/Language-C%2B%2B20%20%7C%20Python%203.13-blue.svg)](#)
[![Cryptography](https://img.shields.io/badge/Cryptography-NIST%20SHA--256%20%7C%20RSA--2048-purple.svg)](#)
[![Consensus](https://img.shields.io/badge/Consensus-Proof--of--Work%20(PoW)-orange.svg)](#)
[![Security](https://img.shields.io/badge/Security-Zero--Plaintext%20Storage-emerald.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-22%2F22%20Unit%20Tests%20Passing-brightgreen.svg)](#)

An enterprise-grade, decentralized electronic voting system engineered in **modern C++20** with native OS-level **NIST SHA-256** cryptographic hashing, **RSA 2048-bit asymmetric digital signatures**, Proof-of-Work (PoW) consensus, and a full-featured **interactive Web Dashboard**. 

Designed to eliminate election fraud, prevent double-voting, protect voter privacy via cryptographically salted pseudonyms, and guarantee individual ballot verifiability without compromising ballot secrecy.

---

## Key Highlights

- **Native C++20 Blockchain Core**: Clean, modular Object-Oriented Architecture (`Block`, `Blockchain`, `Vote`, `Voter`, `Crypto`, `LedgerStorage`, `Authentication`).
- **Asymmetric Digital Signatures**: Every valid vote transaction is digitally signed with the voter's private key (RSA-2048 / PKCS#1 v1.5) and verified against their public key before block mining.
- **Strict Ledger Immutability**: Cryptographic SHA-256 parent hash linking and proof-of-work mining guarantee that historical votes cannot be altered or retroactively manipulated.
- **Double-Voting Prevention**: Multi-layered defense tracking both registered voter identity and on-chain pseudonymous hashes.
- **Zero-Plaintext Credential Storage**: Voter and admin passwords are protected with CSPRNG random salting and multi-iteration key stretching.
- **Individual Ballot Verifiability**: Voters receive a cryptographic `BallotReceipt` with a unique proof code enabling them to audit their vote on-chain without disclosing candidate selection.
- **Interactive Web Dashboard**: Full-featured, responsive browser UI on `http://localhost:5000` with real-time block explorer, candidate tally charts, receipt verification, and interactive tamper simulation.

---

## Transaction Lifecycle Pipeline

```
  ┌─────────────────┐
  │   Create Vote   │ (Ballot ID, Voter Pseudonym, Candidate, Timestamp)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │  Serialize TX   │ (Canonical Payload Generation)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │  RSA-2048 Sign  │ (Sign with Voter's Protected Private Key)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ Verify Sig (PK) │ (Verify Signature using Voter's Public Key)
  └────────┬────────┘
           │
      [Valid Sig]
           │
           ▼
  ┌─────────────────┐
  │ PoW Mine Block  │ (Mine Block satisfying Difficulty Target)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ Append to Chain │ (Store to Immutable Distributed Ledger)
  └─────────────────┘
```

---

## Project Structure

```
├── BlockchainVotingSystem/       # C++20 Core Blockchain Engine
│   ├── include/
│   │   ├── Block.h               # Block header, payload & hashing
│   │   ├── Blockchain.h          # Chain lifecycle, PoW validation & audit
│   │   ├── Crypto.h              # Unified hashing, encryption & digital signatures
│   │   ├── CryptoUtils.h         # Backward-compatible forwarder
│   │   ├── Vote.h               # Ballot transaction model & signature checks
│   │   ├── Voter.h              # Voter identity & asymmetric KeyPair management
│   │   ├── Election.h           # Election manager, state machine & tallying
│   │   ├── BallotReceipt.h      # Individual verifiability cryptographic receipt
│   │   ├── LedgerStorage.h      # Persistent disk I/O & integrity checking
│   │   └── Authentication.h     # Password hashing & brute-force lockout
│   ├── src/
│   │   ├── Block.cpp             # Block hashing, mining & formatting
│   │   ├── Blockchain.cpp        # Chain lifecycle, validation & tamper detection
│   │   ├── Crypto.cpp            # RSA-2048 keygen, signing & verification
│   │   ├── Vote.cpp             # Vote serialization & digital signature verification
│   │   ├── Voter.cpp            # Keypair generation & voter pseudonym hashing
│   │   ├── Election.cpp         # Transaction flow & audit tally
│   │   ├── BallotReceipt.cpp    # Receipt generator and verification
│   │   ├── LedgerStorage.cpp    # Disk file persistence & tamper checking
│   │   ├── Authentication.cpp   # Multi-iteration password stretching
│   │   └── main.cpp             # Console interactive menu & automated demo
│   ├── tests/
│   │   └── test_blockchain.cpp  # 22 automated cryptographic unit tests
│   ├── CMakeLists.txt           # Standard CMake build configuration
│   └── build.ps1                # PowerShell / MinGW compilation script
├── web_app.py                   # Flask Web Dashboard & REST API
├── requirements.txt             # Python web dependencies
├── Procfile                     # Cloud deployment configuration
├── .gitignore                   # Git exclusion rules
└── README.md                    # Project documentation
```

---

## Quick Start Guide

### 1. Run the Web Dashboard (Recommended)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start local web server
python web_app.py
```
Open your browser and navigate to **[http://localhost:5000](http://localhost:5000)**.

---

### 2. Build & Run C++ Engine (Console CLI & Unit Tests)

#### Using PowerShell (Windows):
```powershell
.\build.ps1
```

#### Run Automated Security Demonstration:
```powershell
.\BlockchainVotingSystem\BlockchainVotingSystem.exe --demo
```

#### Run Unit Test Suite (22/22 Passing):
```powershell
.\BlockchainVotingSystem\test_blockchain.exe
```

---

## Unit Test Coverage (22/22 Passed)

```
==========================================================
  RUNNING BLOCKCHAIN & VOTING SYSTEM UNIT TEST SUITE      
==========================================================
[TEST 1/17] Running SHA-256 standard test vectors...       -> PASSED
[TEST 2/17] Running Genesis Block creation test...         -> PASSED
[TEST 3/17] Running Block addition & hash linking test...  -> PASSED
[TEST 4/17] Running Tamper Resistance & Detection test...  -> PASSED
[TEST 5/17] Running Vote serialization & signature test... -> PASSED
[TEST 6/17] Running Election double-voting defense test... -> PASSED
[TEST 7/17] Running Unregistered voter rejection test...   -> PASSED
[TEST 8/17] Running Election Audit & Vote Tallying test... -> PASSED
[TEST 9/17] Running Individual Verifiability receipt test..-> PASSED
[TEST 10/17] Running Ledger Persistence (Save & Load) test.-> PASSED
[TEST 11/17] Running Disk Tampering Detection test...      -> PASSED
[TEST 12/17] Running Password Hashing & Verification test. -> PASSED
[TEST 13/17] Running Input Validation test...              -> PASSED
[TEST 14/17] Running Admin Authentication test...          -> PASSED
[TEST 15/17] Running Voter Registration & Session test...  -> PASSED
[TEST 16/17] Running Brute-Force Lockout Defense test...   -> PASSED
[TEST 17/17] Running Election Lifecycle & Candidate Mgmt.. -> PASSED
[TEST 18/22] Running Digital Signature generation & valid. -> PASSED
[TEST 19/22] Running Digital Signature tampered payload... -> PASSED
[TEST 20/22] Running Digital Signature corrupted sig test. -> PASSED
[TEST 21/22] Running Digital Signature wrong public key... -> PASSED
[TEST 22/22] Running Full Digital Signature Voting Pipeline-> PASSED
==========================================================
        ALL UNIT TESTS PASSED SUCCESSFULLY (22/22)        
==========================================================
```

---

## Free Cloud Deployment (Deploy to Render in 2 Minutes)

You can host this project online for free to get a live URL (e.g. `https://blockchain-voting.onrender.com`) to display on your resume:

1. Push this repository to your **GitHub** account.
2. Sign in to **[Render.com](https://render.com/)** (Free tier).
3. Click **New +** $\rightarrow$ **Web Service**.
4. Connect your GitHub repository.
5. Set:
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn web_app:app`
6. Click **Deploy Web Service**! Your live link will be ready in under 2 minutes.

---

## Security & Architectural Guarantees

| Attack Vector | Defense Mechanism | Outcome |
| :--- | :--- | :--- |
| **Ballot Tampering** | Asymmetric RSA-2048 Digital Signatures & SHA-256 Block Hashing | Immediate verification failure; rejected on-chain. |
| **Double-Voting** | Dual-Layer Check (Voter ID + Cryptographic Voter Pseudonym) | Second ballot attempt denied with `VotingException`. |
| **Voter Privacy Breach** | Salted CSPRNG Pseudonymization (Zero plain voter ID on ledger) | Voter identity decoupled from candidate selection. |
| **History Rewriting (51%)** | Proof-of-Work (PoW) Mining Consensus & Difficulty Target | Computationally infeasible to alter prior blocks. |
| **Credential Theft** | Salted Multi-Iteration Password Stretching + Lockout Defense | Protection against dictionary and brute-force attacks. |

---

## Author

**Parv Jain**  
B.Tech — *Internet of Things, Cyber Security & Blockchain Technology*  
Gyan Ganga Institute of Technology

