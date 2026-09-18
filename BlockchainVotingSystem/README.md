# Secure and Tamper-Resistant Blockchain-Based Electronic Voting System Using C++

An enterprise-grade, object-oriented foundational blockchain and electronic voting system implementation designed for secure, transparent, and tamper-resistant elections. Developed in modern **C++20** with clean modular architecture, hardware/OS-level **NIST SHA-256** cryptography, salted multi-iteration password hashing, double-voting prevention, and cryptographic audit tallying.

---

## Architecture & Project Structure

```
BlockchainVotingSystem/
├── CMakeLists.txt              # Standard CMake build configuration (C++20)
├── README.md                   # Project documentation & usage guide
├── build.ps1                   # Direct build script for PowerShell/MinGW
├── include/
│   ├── Block.h                 # Block class definition (Header)
│   ├── Blockchain.h            # Blockchain class definition (Header)
│   ├── Crypto.h                # [NEW] Digital signatures, RSA keygen, SHA-256 & CSPRNG (Header)
│   ├── CryptoUtils.h           # Backward-compatible forwarder to Crypto.h (Header)
│   ├── Vote.h                 # Ballot transaction model with digital signature (Header)
│   ├── Voter.h                # Voter identity & asymmetric keypair management (Header)
│   ├── Election.h             # Election lifecycle, validation & tallying (Header)
│   ├── BallotReceipt.h        # Individual verifiability cryptographic receipt (Header)
│   ├── LedgerStorage.h        # Persistent disk I/O & integrity verification (Header)
│   └── Authentication.h       # Admin/voter authentication & password hashing (Header)
├── src/
│   ├── Block.cpp               # Block hashing, mining & formatting implementation
│   ├── Blockchain.cpp          # Chain lifecycle, validation & tamper detection
│   ├── Crypto.cpp              # [NEW] RSA 2048-bit digital signatures & Windows CryptoAPI
│   ├── CryptoUtils.cpp         # Forwarder to Crypto.cpp
│   ├── Vote.cpp               # Vote serialization & digital signature verification
│   ├── Voter.cpp              # Keypair generation & voter pseudonym hashing
│   ├── Election.cpp           # Election manager, transaction flow & audit tally
│   ├── BallotReceipt.cpp      # Verification receipt generator and lookup
│   ├── LedgerStorage.cpp      # Disk file persistence & tamper checking
│   ├── Authentication.cpp     # Password hashing, auth & brute-force lockout
│   └── main.cpp                # Main Menu, Admin Menu, Voter Menu & automated demo
├── data/                       # Directory for persistent blockchain ledgers & voter registry
└── tests/                      # Directory for unit tests and security validations
    └── test_blockchain.cpp     # 22 automated unit tests verifying cryptographic invariants
```

---

## Core Components

### 1. `Authentication` Class
- **Admin & Voter Authentication**: Secure login workflows for election administrators and registered voters.
- **Zero Plaintext Storage**: Passwords are never stored in plain text. Uses CSPRNG-generated 16-byte random salts and multi-round (10,000 iterations) SHA-256 key stretching:
  $$\text{StoredHash} = \text{iterations} \mathbin{\$} \text{salt} \mathbin{\$} \text{stretchedHash}$$
- **Side-Channel Timing Defense**: Uses constant-time string comparison (`Crypto::constantTimeEquals`) during verification.
- **Input Validation**: Enforces strict constraints on usernames (3-32 characters, alphanumeric, underscores, hyphens) and passwords (minimum 6 characters).
- **Failed-Login Handling & Brute-Force Lockout**: Tracks consecutive failed login attempts; automatically locks out accounts for 30 seconds after 3 failed attempts.
- **Session Management**: Successful voter authentication returns a `VoterSession` containing voter ID, cryptographic pseudonym, session token, and login timestamp.

### 2. `Election` Lifecycle & Candidate Management
- **State Machine**: Supports `NOT_STARTED`, `IN_PROGRESS` (Active), and `ENDED` (Concluded) states.
- **Admin Controls**: Administrators can add candidates, remove candidates (before election start), register voters, start elections, and close elections.
- **Vote Safeguards**: Voting is strictly locked unless the election state is `IN_PROGRESS`.

### 3. `Block` & `Blockchain` Classes
- **Block**: `index`, `timestamp`, `data`, `previousHash`, `hash`, `nonce`, dynamic SHA-256 calculation, proof-of-work mining.
- **Blockchain**: Automatic Genesis Block #0 creation, tamper detection, proof-of-work validation, and link verification.

### 4. `Vote` & `BallotReceipt`
- **Secret Ballot & Voter Privacy**: Salted SHA-256 voter pseudonym (`VoterHash`) ensures ballot anonymity on the public ledger.
- **Individual Verifiability**: Voters receive a cryptographic `BallotReceipt` proving their ballot was included in Block #X without disclosing who they voted for.

---

## Menu Navigation

### Main Menu
```
1. Admin Login
2. Voter Registration
3. Voter Login
4. View Candidates
5. Exit
```

### Admin Menu
```
1. Add Candidate
2. Remove Candidate
3. View Candidates
4. Register Voter
5. Start Election
6. End Election
7. Logout
```

### Voter Menu
```
1. View Candidates
2. Logout
(Plus direct vote casting when election is active)
```

---

## Building and Running

### Build & Run Tests
```powershell
.\build.ps1
```

### Run Interactive Console
```powershell
.\BlockchainVotingSystem\BlockchainVotingSystem.exe
```

### Run Automated Security Demo
```powershell
.\BlockchainVotingSystem\BlockchainVotingSystem.exe --demo
```

---

## Cryptographic Digital Signatures Subsystem

- **Asymmetric Key Pair Generation**: Each registered voter is automatically provisioned an authentic RSA 2048-bit key pair (`generateKeyPair`) using OS-level entropy.
- **Transaction Signing**: Valid votes are canonically serialized and digitally signed with the voter's private key (`signTransaction`).
- **Signature Verification**: Signatures are cryptographically verified against the voter's public key (`verifySignature`) prior to block mining.
- **Tamper Rejection**: Any alteration to candidate choices, ballot IDs, or signature bytes immediately invalidates the cryptographic proof and triggers rejection.
- **Non-Repudiation**: Private keys are strictly protected in memory and never published to the public blockchain ledger; only public keys and digital signatures reside on-chain.

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
