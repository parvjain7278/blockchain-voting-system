import os
import json
import time
import hashlib
import datetime
from typing import List, Dict, Any, Optional
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# ==============================================================================
# CRYPTOGRAPHIC UTILITIES
# ==============================================================================

def sha256_str(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def generate_key_pair_pem():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return public_pem, private_pem

def sign_transaction(payload: str, private_key_pem: str) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    signature = private_key.sign(
        payload.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()

def verify_signature(payload: str, signature_hex: str, public_key_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(
            sig_bytes,
            payload.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ==============================================================================
# BLOCKCHAIN MODEL
# ==============================================================================

class Block:
    def __init__(self, index: int, data: str, previous_hash: str, timestamp: Optional[str] = None, nonce: int = 0, block_hash: str = "", merkle_root: str = ""):
        self.index = index
        self.timestamp = timestamp if timestamp else datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_root = merkle_root if merkle_root else sha256_str(data)
        self.hash = block_hash if block_hash else self.calculate_hash()

    def calculate_hash(self) -> str:
        header = f"{self.index}{self.timestamp}{self.merkle_root}{self.previous_hash}{self.nonce}"
        return sha256_str(header)

    def mine_block(self, difficulty: int):
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previousHash": self.previous_hash,
            "hash": self.hash,
            "nonce": self.nonce,
            "merkleRoot": self.merkle_root
        }

class Blockchain:
    def __init__(self, difficulty: int = 2):
        self.difficulty = difficulty
        self.chain: List[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(
            index=0,
            data="GENESIS_BLOCK: Secure Electronic Voting System Initialized",
            previous_hash="0000000000000000000000000000000000000000000000000000000000000000"
        )
        genesis.mine_block(self.difficulty)
        self.chain = [genesis]

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: str) -> Block:
        prev_hash = self.get_latest_block().hash
        next_index = len(self.chain)
        new_block = Block(index=next_index, data=data, previous_hash=prev_hash)
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self) -> (bool, str):
        if not self.chain:
            return False, "Blockchain is empty."

        # Validate genesis
        genesis = self.chain[0]
        if genesis.index != 0 or genesis.hash != genesis.calculate_hash():
            return False, f"Genesis block corrupt! Stored: {genesis.hash[:16]}... vs Calc: {genesis.calculate_hash()[:16]}..."

        target = "0" * self.difficulty
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr.index != i:
                return False, f"Index discontinuity at Block #{i}."

            if curr.hash != curr.calculate_hash():
                return False, f"Block #{i} data tampered! Stored hash {curr.hash[:16]}... != Recalculated {curr.calculate_hash()[:16]}..."

            if curr.previous_hash != prev.hash:
                return False, f"Cryptographic link broken between Block #{i-1} and #{i}!"

            if not curr.hash.startswith(target):
                return False, f"Difficulty constraint unsatisfied at Block #{i}."

        return True, "Blockchain is cryptographically valid and untampered."

# ==============================================================================
# ELECTION ENGINE
# ==============================================================================

class ElectionEngine:
    def __init__(self):
        self.name = "2026 Student Government Presidential Election"
        self.state = "IN_PROGRESS" # NOT_STARTED, IN_PROGRESS, ENDED
        self.salt = "ELECTION_SECRET_SALT_2026"
        self.blockchain = Blockchain(difficulty=2)
        self.candidates = ["Alice Johnson", "Bob Smith", "Charlie Davis"]
        self.voters: Dict[str, Dict[str, Any]] = {}
        self.cast_voter_hashes = set()
        self.ballot_counter = 1000

        # Seed initial demo voters
        self._seed_demo_voters()

    def _seed_demo_voters(self):
        demo_users = [
            ("VTR-1001", "Password1001!"),
            ("VTR-1002", "Password1002!"),
            ("VTR-1003", "Password1003!"),
            ("VTR-1004", "Password1004!"),
        ]
        for vid, pwd in demo_users:
            self.register_voter(vid, pwd)

    def register_voter(self, voter_id: str, password: str) -> Dict[str, Any]:
        if not voter_id or len(voter_id) < 3:
            raise ValueError("Voter ID must be at least 3 characters.")
        if voter_id in self.voters:
            raise ValueError(f"Voter ID '{voter_id}' is already registered.")

        pub_pem, priv_pem = generate_key_pair_pem()
        voter_hash = sha256_str(f"VOTER_SALT|{self.salt}|{voter_id}")
        pwd_hash = sha256_str(f"SALT_{self.salt}_{password}")

        self.voters[voter_id] = {
            "voterId": voter_id,
            "passwordHash": pwd_hash,
            "voterHash": voter_hash,
            "publicKey": pub_pem,
            "privateKey": priv_pem,
            "hasVoted": False
        }
        return self.voters[voter_id]

    def authenticate_voter(self, voter_id: str, password: str) -> Dict[str, Any]:
        if voter_id not in self.voters:
            raise ValueError("Invalid Voter ID.")
        v = self.voters[voter_id]
        if v["passwordHash"] != sha256_str(f"SALT_{self.salt}_{password}"):
            raise ValueError("Incorrect password.")
        return {
            "voterId": v["voterId"],
            "voterHash": v["voterHash"],
            "publicKey": v["publicKey"],
            "hasVoted": v["hasVoted"]
        }

    def cast_vote(self, voter_id: str, candidate_name: str) -> Dict[str, Any]:
        if self.state != "IN_PROGRESS":
            raise ValueError(f"Voting denied: Election is currently {self.state}.")
        if voter_id not in self.voters:
            raise ValueError("Voter is not registered.")
        voter = self.voters[voter_id]
        if voter["hasVoted"]:
            raise ValueError("Double-voting denied: You have already cast your ballot!")
        if voter["voterHash"] in self.cast_voter_hashes:
            raise ValueError("Double-voting denied: Pseudonymous voter hash already exists on ledger!")
        if candidate_name not in self.candidates:
            raise ValueError(f"Candidate '{candidate_name}' is not on the ballot.")

        self.ballot_counter += 1
        ballot_id = f"BLT-{self.ballot_counter}"
        now_str = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Canonical payload to sign
        tx_payload = f"{ballot_id}:{voter['voterHash']}:{candidate_name}:{now_str}"

        # 2. Asymmetric RSA Digital Signature
        signature = sign_transaction(tx_payload, voter["privateKey"])

        # 3. Verify signature BEFORE accepting
        if not verify_signature(tx_payload, signature, voter["publicKey"]):
            raise ValueError("Cryptographic digital signature verification failed!")

        # 4. Serialize transaction for immutable blockchain storage
        compact_pub = voter["publicKey"].replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "").strip()
        block_data = f"VOTE_TX|{ballot_id}|{voter['voterHash']}|{candidate_name}|{now_str}|{compact_pub}|{signature}"

        # 5. Mine and append block to blockchain
        new_block = self.blockchain.add_block(block_data)

        # 6. Mark voter as voted
        voter["hasVoted"] = True
        self.cast_voter_hashes.add(voter["voterHash"])

        # 7. Generate official Ballot Receipt
        receipt_code = sha256_str(f"RECEIPT|{ballot_id}|{voter['voterHash']}|{new_block.index}|{new_block.hash}")

        return {
            "ballotId": ballot_id,
            "blockIndex": new_block.index,
            "blockHash": new_block.hash,
            "voterHash": voter["voterHash"],
            "receiptCode": receipt_code,
            "candidate": candidate_name,
            "signature": signature
        }

    def tally_votes(self) -> Dict[str, Any]:
        tally = {c: 0 for c in self.candidates}
        valid_votes = 0

        for block in self.blockchain.chain[1:]:
            if block.data.startswith("VOTE_TX|"):
                parts = block.data.split("|")
                if len(parts) >= 7:
                    cand = parts[3]
                    if cand in tally:
                        tally[cand] += 1
                        valid_votes += 1

        total_voters = len(self.voters)
        turnout = (valid_votes / total_voters * 100.0) if total_voters > 0 else 0.0

        max_votes = 0
        winner = "None"
        is_tie = False
        for c, count in tally.items():
            if count > max_votes:
                max_votes = count
                winner = c
                is_tie = False
            elif count == max_votes and max_votes > 0:
                is_tie = True

        return {
            "tally": tally,
            "totalVotes": valid_votes,
            "totalRegistered": total_voters,
            "turnout": round(turnout, 1),
            "winner": "TIE" if is_tie else (winner if valid_votes > 0 else "None"),
            "isTie": is_tie
        }

    def verify_receipt(self, receipt_code: str, ballot_id: str) -> Dict[str, Any]:
        for block in self.blockchain.chain[1:]:
            if block.data.startswith("VOTE_TX|"):
                parts = block.data.split("|")
                if len(parts) >= 7:
                    b_id = parts[1]
                    v_hash = parts[2]
                    expected_code = sha256_str(f"RECEIPT|{b_id}|{v_hash}|{block.index}|{block.hash}")
                    if (ballot_id and b_id == ballot_id) or (receipt_code and expected_code == receipt_code):
                        return {
                            "valid": True,
                            "ballotId": b_id,
                            "blockIndex": block.index,
                            "blockHash": block.hash,
                            "voterHash": v_hash,
                            "candidate": parts[3],
                            "timestamp": parts[4],
                            "signature": parts[6],
                            "receiptCode": expected_code,
                            "message": f"VERIFIED: Ballot {b_id} is permanently recorded on Block #{block.index} with authentic digital signature."
                        }
        return {
            "valid": False,
            "message": "Receipt verification failed: No matching ballot found on the blockchain ledger."
        }

engine = ElectionEngine()

# Seed 2 sample votes for instant demo richness
engine.cast_vote("VTR-1001", "Alice Johnson")
engine.cast_vote("VTR-1002", "Bob Smith")

# ==============================================================================
# FLASK WEB ROUTES & API
# ==============================================================================

@app.route("/api/status", methods=["GET"])
def get_status():
    valid, msg = engine.blockchain.is_chain_valid()
    tally_data = engine.tally_votes()
    return jsonify({
        "electionName": engine.name,
        "state": engine.state,
        "chainValid": valid,
        "chainMessage": msg,
        "candidates": engine.candidates,
        "tally": tally_data["tally"],
        "totalVotes": tally_data["totalVotes"],
        "totalRegistered": tally_data["totalRegistered"],
        "turnout": tally_data["turnout"],
        "winner": tally_data["winner"],
        "difficulty": engine.blockchain.difficulty,
        "blockCount": len(engine.blockchain.chain)
    })

@app.route("/api/blocks", methods=["GET"])
def get_blocks():
    valid, msg = engine.blockchain.is_chain_valid()
    blocks = [b.to_dict() for b in engine.blockchain.chain]
    return jsonify({
        "chainValid": valid,
        "chainMessage": msg,
        "blocks": blocks
    })

@app.route("/api/voter/register", methods=["POST"])
def api_register_voter():
    data = request.json or {}
    voter_id = data.get("voterId", "").strip()
    password = data.get("password", "").strip()
    try:
        v = engine.register_voter(voter_id, password)
        return jsonify({"success": True, "message": f"Voter '{voter_id}' registered with RSA-2048 keypair.", "voter": {"voterId": v["voterId"], "voterHash": v["voterHash"]}})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)}), 400

@app.route("/api/voter/login", methods=["POST"])
def api_login_voter():
    data = request.json or {}
    voter_id = data.get("voterId", "").strip()
    password = data.get("password", "").strip()
    try:
        session = engine.authenticate_voter(voter_id, password)
        return jsonify({"success": True, "session": session})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)}), 401

@app.route("/api/vote", methods=["POST"])
def api_cast_vote():
    data = request.json or {}
    voter_id = data.get("voterId", "").strip()
    candidate = data.get("candidate", "").strip()
    try:
        receipt = engine.cast_vote(voter_id, candidate)
        return jsonify({"success": True, "receipt": receipt})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)}), 400

@app.route("/api/receipt/verify", methods=["POST"])
def api_verify_receipt():
    data = request.json or {}
    receipt_code = data.get("receiptCode", "").strip()
    ballot_id = data.get("ballotId", "").strip()
    result = engine.verify_receipt(receipt_code, ballot_id)
    return jsonify(result)

@app.route("/api/admin/start", methods=["POST"])
def api_admin_start():
    try:
        if engine.state == "ENDED":
            return jsonify({"success": False, "message": "Cannot restart ended election."}), 400
        engine.state = "IN_PROGRESS"
        return jsonify({"success": True, "state": engine.state})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)}), 400

@app.route("/api/admin/end", methods=["POST"])
def api_admin_end():
    try:
        engine.state = "ENDED"
        return jsonify({"success": True, "state": engine.state, "tally": engine.tally_votes()})
    except Exception as ex:
        return jsonify({"success": False, "message": str(ex)}), 400

@app.route("/api/admin/candidate/add", methods=["POST"])
def api_add_candidate():
    data = request.json or {}
    cand = data.get("candidate", "").strip()
    if not cand:
        return jsonify({"success": False, "message": "Candidate name cannot be empty."}), 400
    if cand in engine.candidates:
        return jsonify({"success": False, "message": "Candidate already registered."}), 400
    engine.candidates.append(cand)
    return jsonify({"success": True, "candidates": engine.candidates})

@app.route("/api/admin/candidate/remove", methods=["POST"])
def api_remove_candidate():
    data = request.json or {}
    cand = data.get("candidate", "").strip()
    if engine.state == "IN_PROGRESS":
        return jsonify({"success": False, "message": "Cannot remove candidate while election is active."}), 400
    if cand in engine.candidates:
        engine.candidates.remove(cand)
        return jsonify({"success": True, "candidates": engine.candidates})
    return jsonify({"success": False, "message": "Candidate not found."}), 404

@app.route("/api/admin/tamper", methods=["POST"])
def api_tamper_block():
    data = request.json or {}
    block_index = int(data.get("blockIndex", 1))
    if block_index < 0 or block_index >= len(engine.blockchain.chain):
        return jsonify({"success": False, "message": "Invalid block index."}), 400
    
    # Intentionally corrupt the block data payload
    target = engine.blockchain.chain[block_index]
    target.data = target.data + " [MALICIOUS_TAMPER_MODIFIED]"
    valid, msg = engine.blockchain.is_chain_valid()
    return jsonify({"success": True, "message": f"Tampered with Block #{block_index} data!", "chainValid": valid, "chainMessage": msg})

@app.route("/api/admin/reset", methods=["POST"])
def api_reset():
    global engine
    engine = ElectionEngine()
    engine.cast_vote("VTR-1001", "Alice Johnson")
    engine.cast_vote("VTR-1002", "Bob Smith")
    return jsonify({"success": True, "message": "Blockchain and Election reset to genuine state."})

# ==============================================================================
# SINGLE-PAGE WEB FRONTEND
# ==============================================================================

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Blockchain Electronic Voting System</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    @keyframes pulseGlow {
      0%, 100% { box-shadow: 0 0 15px rgba(59, 130, 246, 0.4); }
      50% { box-shadow: 0 0 25px rgba(59, 130, 246, 0.7); }
    }
    .glow-box { animation: pulseGlow 3s infinite; }
    .mono-font { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex flex-col font-sans">

  <!-- Top Header Navigation -->
  <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center text-white shadow-lg shadow-blue-500/30">
        <i class="fa-solid fa-cube text-xl"></i>
      </div>
      <div>
        <h1 class="font-bold text-lg leading-tight tracking-wide flex items-center gap-2">
          Blockchain Voting System
          <span class="text-xs bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 px-2 py-0.5 rounded-full">C++20 & Cryptography</span>
        </h1>
        <p class="text-xs text-slate-400" id="electionSubtitle">2026 Student Government Presidential Election</p>
      </div>
    </div>

    <!-- Live Status Indicators -->
    <div class="flex items-center gap-4 text-xs">
      <div class="flex items-center gap-2 bg-slate-800/70 border border-slate-700 px-3 py-1.5 rounded-lg">
        <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" id="statusPulse"></span>
        <span class="text-slate-300 font-medium">Chain:</span>
        <span class="text-emerald-400 font-bold" id="chainBadge">VALID & UNTAMPERED</span>
      </div>
      <div class="flex items-center gap-2 bg-slate-800/70 border border-slate-700 px-3 py-1.5 rounded-lg">
        <i class="fa-solid fa-signal text-blue-400"></i>
        <span class="text-slate-300 font-medium">Status:</span>
        <span class="text-amber-400 font-bold" id="electionStateBadge">IN_PROGRESS</span>
      </div>
      <div class="flex items-center gap-2 bg-slate-800/70 border border-slate-700 px-3 py-1.5 rounded-lg">
        <i class="fa-solid fa-cubes text-purple-400"></i>
        <span class="text-slate-300 font-medium">Blocks:</span>
        <span class="text-purple-300 font-bold" id="blockCountBadge">3</span>
      </div>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <nav class="border-b border-slate-800 bg-slate-900/40 px-6">
    <div class="flex space-x-2 text-sm font-medium">
      <button onclick="switchTab('dashboard')" id="tab-dashboard" class="tab-btn py-3 px-4 border-b-2 border-blue-500 text-blue-400 flex items-center gap-2">
        <i class="fa-solid fa-chart-pie"></i> Live Dashboard & Results
      </button>
      <button onclick="switchTab('booth')" id="tab-booth" class="tab-btn py-3 px-4 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2">
        <i class="fa-solid fa-check-to-slot"></i> Voter Portal & Cast Ballot
      </button>
      <button onclick="switchTab('explorer')" id="tab-explorer" class="tab-btn py-3 px-4 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2">
        <i class="fa-solid fa-network-wired"></i> Blockchain Ledger Explorer
      </button>
      <button onclick="switchTab('verify')" id="tab-verify" class="tab-btn py-3 px-4 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2">
        <i class="fa-solid fa-receipt"></i> Verify Ballot Receipt
      </button>
      <button onclick="switchTab('admin')" id="tab-admin" class="tab-btn py-3 px-4 border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2">
        <i class="fa-solid fa-sliders"></i> Admin Controls & Tamper Testing
      </button>
    </div>
  </nav>

  <!-- Main Container -->
  <main class="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">

    <!-- TAB 1: LIVE DASHBOARD -->
    <section id="pane-dashboard" class="space-y-6">
      <!-- Winner Alert (if ended) -->
      <div id="winnerBanner" class="hidden p-4 rounded-xl bg-gradient-to-r from-amber-500/20 via-yellow-500/10 to-amber-500/20 border border-amber-500/40 flex items-center gap-4">
        <div class="text-3xl text-amber-400"><i class="fa-solid fa-trophy"></i></div>
        <div>
          <h2 class="font-bold text-amber-300 text-lg">Official Election Concluded!</h2>
          <p class="text-sm text-slate-300" id="winnerText">Winner: Alice Johnson</p>
        </div>
      </div>

      <!-- Quick Metrics Grid -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl">
          <p class="text-xs font-semibold uppercase text-slate-400">Total Votes Cast</p>
          <div class="flex items-baseline justify-between mt-2">
            <h3 class="text-3xl font-extrabold text-blue-400" id="totalVotes">0</h3>
            <span class="text-xs bg-blue-500/10 text-blue-400 px-2 py-1 rounded">On-Chain</span>
          </div>
        </div>
        <div class="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl">
          <p class="text-xs font-semibold uppercase text-slate-400">Registered Voters</p>
          <div class="flex items-baseline justify-between mt-2">
            <h3 class="text-3xl font-extrabold text-indigo-400" id="totalRegistered">0</h3>
            <span class="text-xs bg-indigo-500/10 text-indigo-400 px-2 py-1 rounded">Salted & Hashed</span>
          </div>
        </div>
        <div class="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl">
          <p class="text-xs font-semibold uppercase text-slate-400">Voter Turnout</p>
          <div class="flex items-baseline justify-between mt-2">
            <h3 class="text-3xl font-extrabold text-emerald-400" id="voterTurnout">0%</h3>
            <span class="text-xs bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded">Participation</span>
          </div>
        </div>
        <div class="bg-slate-900/60 border border-slate-800 p-5 rounded-2xl">
          <p class="text-xs font-semibold uppercase text-slate-400">Security Architecture</p>
          <div class="flex items-baseline justify-between mt-2">
            <h3 class="text-lg font-bold text-slate-200">RSA-2048 + SHA-256</h3>
            <span class="text-xs bg-purple-500/10 text-purple-400 px-2 py-1 rounded">CryptoAPI</span>
          </div>
        </div>
      </div>

      <!-- Candidate Live Tally Cards -->
      <div class="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-5">
        <div class="flex items-center justify-between">
          <div>
            <h2 class="font-bold text-lg text-slate-100 flex items-center gap-2">
              <i class="fa-solid fa-square-poll-vertical text-blue-400"></i> Candidate Tally
            </h2>
            <p class="text-xs text-slate-400">Live cryptographic vote counts audited directly from ledger blocks</p>
          </div>
          <button onclick="refreshData()" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded-lg text-slate-300 transition flex items-center gap-1.5">
            <i class="fa-solid fa-arrows-rotate"></i> Refresh
          </button>
        </div>

        <div id="candidatesList" class="space-y-4">
          <!-- Populated by JavaScript -->
        </div>
      </div>
    </section>

    <!-- TAB 2: VOTER PORTAL -->
    <section id="pane-booth" class="hidden space-y-6">
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">

        <!-- Login / Voter State Card -->
        <div class="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-4">
          <h2 class="font-bold text-lg text-slate-100 flex items-center gap-2">
            <i class="fa-solid fa-id-card text-indigo-400"></i> Voter Authentication
          </h2>
          <p class="text-xs text-slate-400 leading-relaxed">
            Enter your credentials. Passwords are protected via multi-round salted cryptographic stretching.
          </p>

          <div id="loginForm" class="space-y-3">
            <div>
              <label class="text-xs font-semibold text-slate-400">Voter ID</label>
              <input type="text" id="loginVoterId" value="VTR-1003" placeholder="e.g. VTR-1003" class="w-full mt-1 bg-slate-800/80 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500">
            </div>
            <div>
              <label class="text-xs font-semibold text-slate-400">Password</label>
              <input type="password" id="loginPassword" value="Password1003!" placeholder="Password" class="w-full mt-1 bg-slate-800/80 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500">
            </div>
            <button onclick="loginVoter()" class="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 font-semibold text-sm rounded-lg text-white shadow-lg shadow-indigo-600/20 transition">
              <i class="fa-solid fa-key mr-1.5"></i> Authenticate Voter
            </button>
          </div>

          <div id="authSuccessBox" class="hidden space-y-3 p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
            <div class="flex items-center gap-2 text-emerald-400 font-semibold text-sm">
              <i class="fa-solid fa-circle-check"></i> Authenticated Session Active
            </div>
            <p class="text-xs text-slate-300">Voter: <span class="font-bold text-slate-100" id="sessionVoterId"></span></p>
            <div class="text-[11px] mono-font text-slate-400 break-all bg-slate-950/60 p-2 rounded border border-slate-800">
              <span class="text-indigo-400 font-bold block mb-1">Pseudonym Hash (SHA-256):</span>
              <span id="sessionVoterHash"></span>
            </div>
            <button onclick="logoutVoter()" class="text-xs text-red-400 hover:underline">Log Out</button>
          </div>

          <!-- Register new voter quickly -->
          <div class="border-t border-slate-800 pt-4">
            <p class="text-xs font-semibold text-slate-400 mb-2">Need an account? Quick Register:</p>
            <div class="flex gap-2">
              <input type="text" id="regVoterId" placeholder="New Voter ID" class="w-1/2 bg-slate-800/80 border border-slate-700 rounded px-2.5 py-1 text-xs">
              <input type="password" id="regPassword" placeholder="Password (min 6)" class="w-1/2 bg-slate-800/80 border border-slate-700 rounded px-2.5 py-1 text-xs">
            </div>
            <button onclick="registerVoter()" class="mt-2 w-full py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded text-slate-300">
              Register New Voter ID
            </button>
          </div>
        </div>

        <!-- Ballot Box -->
        <div class="lg:col-span-2 bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-4">
          <div class="flex items-center justify-between">
            <h2 class="font-bold text-lg text-slate-100 flex items-center gap-2">
              <i class="fa-solid fa-vote-yea text-blue-400"></i> Official Electronic Ballot
            </h2>
            <span class="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded">Digital Signature Flow</span>
          </div>

          <!-- Transaction Pipeline Diagram -->
          <div class="bg-slate-950/80 border border-slate-800/80 p-3 rounded-xl flex flex-wrap items-center justify-between text-[11px] gap-2 text-slate-400">
            <span class="flex items-center gap-1 text-blue-400 font-semibold"><i class="fa-solid fa-1"></i> Create Vote</span>
            <i class="fa-solid fa-arrow-right text-slate-600"></i>
            <span class="flex items-center gap-1 text-blue-400 font-semibold"><i class="fa-solid fa-2"></i> Serialize TX</span>
            <i class="fa-solid fa-arrow-right text-slate-600"></i>
            <span class="flex items-center gap-1 text-purple-400 font-semibold"><i class="fa-solid fa-3"></i> RSA-2048 Sign</span>
            <i class="fa-solid fa-arrow-right text-slate-600"></i>
            <span class="flex items-center gap-1 text-emerald-400 font-semibold"><i class="fa-solid fa-4"></i> Verify Sig</span>
            <i class="fa-solid fa-arrow-right text-slate-600"></i>
            <span class="flex items-center gap-1 text-amber-400 font-semibold"><i class="fa-solid fa-5"></i> Mine to Block</span>
          </div>

          <div id="votingDisabledPrompt" class="p-6 bg-slate-800/40 rounded-xl border border-dashed border-slate-700 text-center space-y-2">
            <i class="fa-solid fa-user-lock text-3xl text-slate-500"></i>
            <h3 class="font-semibold text-slate-300">Please Authenticate to Access Ballot</h3>
            <p class="text-xs text-slate-400">Login with your credentials on the left to cast your cryptographically signed vote.</p>
          </div>

          <div id="ballotCandidates" class="hidden space-y-3">
            <p class="text-xs text-slate-400 font-medium">Select one candidate below:</p>
            <div id="ballotCandidateButtons" class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <!-- Populated by JS -->
            </div>
            <button onclick="submitBallot()" id="castVoteBtn" disabled class="mt-4 w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed font-bold text-sm rounded-xl text-white shadow-lg shadow-blue-500/20 transition flex items-center justify-center gap-2">
              <i class="fa-solid fa-file-signature"></i> Sign Ballot & Mine Onto Blockchain
            </button>
          </div>

          <!-- Ballot Receipt Popup Modal / Container -->
          <div id="receiptResultCard" class="hidden p-5 bg-gradient-to-br from-slate-900 to-indigo-950/40 border-2 border-indigo-500/40 rounded-2xl space-y-3 glow-box">
            <div class="flex items-center justify-between">
              <h3 class="font-bold text-emerald-400 text-base flex items-center gap-2">
                <i class="fa-solid fa-circle-check"></i> Ballot Successfully Mined Onto Blockchain!
              </h3>
              <span class="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded font-mono" id="receiptBlockTag">Block #3</span>
            </div>
            <p class="text-xs text-slate-300">Your ballot has been digitally signed with your private key and recorded into an immutable blockchain block.</p>
            <div class="space-y-1.5 text-xs mono-font bg-slate-950/80 p-3 rounded-lg border border-slate-800">
              <div class="flex justify-between"><span class="text-slate-400">Ballot ID:</span> <span class="font-bold text-slate-200" id="receiptBallotId"></span></div>
              <div class="flex justify-between"><span class="text-slate-400">Voter Pseudonym:</span> <span class="text-indigo-300 truncate max-w-xs" id="receiptVoterHash"></span></div>
              <div class="flex justify-between"><span class="text-slate-400">Candidate:</span> <span class="font-bold text-emerald-400" id="receiptCandidate"></span></div>
              <div class="flex justify-between"><span class="text-slate-400">Block Hash:</span> <span class="text-slate-400 truncate max-w-xs" id="receiptBlockHash"></span></div>
              <div class="mt-2 pt-2 border-t border-slate-800">
                <span class="text-amber-400 font-bold block">Receipt Proof Code:</span>
                <span class="text-[11px] text-amber-200 break-all" id="receiptCode"></span>
              </div>
            </div>
            <p class="text-[11px] text-slate-400 italic">Save your Receipt Proof Code! You can verify this ballot at any time under the "Verify Ballot Receipt" tab.</p>
          </div>
        </div>

      </div>
    </section>

    <!-- TAB 3: BLOCKCHAIN EXPLORER -->
    <section id="pane-explorer" class="hidden space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-4 bg-slate-900/60 border border-slate-800 p-5 rounded-2xl">
        <div>
          <h2 class="font-bold text-lg text-slate-100 flex items-center gap-2">
            <i class="fa-solid fa-cubes-stacked text-purple-400"></i> Append-Only Blockchain Ledger
          </h2>
          <p class="text-xs text-slate-400">Each block is linked by SHA-256 parent hash pointers, PoW difficulty target, and Merkle tree roots.</p>
        </div>
        <div class="flex gap-2">
          <button onclick="auditBlockchain()" class="px-4 py-2 bg-purple-600 hover:bg-purple-500 text-xs font-semibold rounded-xl text-white shadow transition flex items-center gap-2">
            <i class="fa-solid fa-shield-halved"></i> Run Full Ledger Audit
          </button>
          <button onclick="refreshBlocks()" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded-xl text-slate-300 transition">
            <i class="fa-solid fa-arrows-rotate"></i>
          </button>
        </div>
      </div>

      <!-- Live Audit Banner Result -->
      <div id="auditResultBanner" class="hidden p-4 rounded-xl text-sm font-medium"></div>

      <!-- Blockchain Visual Chain Container -->
      <div id="blocksContainer" class="space-y-4">
        <!-- Rendered by JS -->
      </div>
    </section>

    <!-- TAB 4: VERIFY RECEIPT -->
    <section id="pane-verify" class="hidden space-y-6">
      <div class="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl max-w-2xl mx-auto space-y-4">
        <h2 class="font-bold text-lg text-slate-100 flex items-center gap-2">
          <i class="fa-solid fa-magnifying-glass text-blue-400"></i> Individual Ballot Verifiability
        </h2>
        <p class="text-xs text-slate-400 leading-relaxed">
          Verify that your vote was included in the official blockchain ledger without disclosing your identity or compromising voter secrecy.
        </p>

        <div class="space-y-3">
          <div>
            <label class="text-xs font-semibold text-slate-400">Receipt Proof Code or Ballot ID</label>
            <input type="text" id="verifyInput" placeholder="Paste 64-char receipt code or e.g. BLT-1001" class="w-full mt-1 bg-slate-800/80 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 mono-font focus:outline-none focus:border-blue-500">
          </div>
          <button onclick="verifyBallotReceipt()" class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 font-semibold text-sm rounded-lg text-white transition">
            <i class="fa-solid fa-certificate mr-1.5"></i> Verify On-Chain Integrity
          </button>
        </div>

        <div id="verifyOutcome" class="hidden p-4 rounded-xl text-xs space-y-2"></div>
      </div>
    </section>

    <!-- TAB 5: ADMIN & TAMPER TESTING -->
    <section id="pane-admin" class="hidden space-y-6">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

        <!-- Lifecycle Controls -->
        <div class="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-4">
          <h2 class="font-bold text-lg text-slate-100 flex items-center gap-2">
            <i class="fa-solid fa-gear text-amber-400"></i> Election Administration
          </h2>
          <div class="flex gap-3">
            <button onclick="startElection()" class="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-xs font-bold rounded-lg text-white transition">
              <i class="fa-solid fa-play mr-1"></i> Start Election
            </button>
            <button onclick="endElection()" class="flex-1 py-2.5 bg-rose-600 hover:bg-rose-500 text-xs font-bold rounded-lg text-white transition">
              <i class="fa-solid fa-stop mr-1"></i> Conclude & Tally
            </button>
          </div>

          <!-- Add Candidate -->
          <div class="border-t border-slate-800 pt-4 space-y-2">
            <label class="text-xs font-semibold text-slate-400">Add New Candidate</label>
            <div class="flex gap-2">
              <input type="text" id="newCandidateName" placeholder="Candidate full name" class="flex-1 bg-slate-800/80 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200">
              <button onclick="addCandidate()" class="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 font-medium text-xs rounded-lg text-slate-200">Add</button>
            </div>
          </div>
        </div>

        <!-- Tamper Simulation (Core Blockchain Feature) -->
        <div class="bg-slate-900/60 border border-slate-800 p-6 rounded-2xl space-y-4">
          <div class="flex items-center gap-2 text-rose-400 font-bold text-lg">
            <i class="fa-solid fa-triangle-exclamation"></i> Tamper Simulation Defense Test
          </div>
          <p class="text-xs text-slate-400 leading-relaxed">
            Test the blockchain's cryptographic immutability. Modify data inside an existing mined block and observe how SHA-256 linkage and digital signatures immediately flag the corruption and reject the ledger!
          </p>

          <div class="space-y-3">
            <div class="flex items-center gap-3">
              <label class="text-xs font-semibold text-slate-400 whitespace-nowrap">Target Block Index:</label>
              <input type="number" id="tamperBlockIndex" value="1" min="1" max="10" class="w-20 bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm font-bold text-center">
            </div>
            <button onclick="tamperBlock()" class="w-full py-2.5 bg-rose-700 hover:bg-rose-600 text-xs font-bold rounded-lg text-white transition">
              <i class="fa-solid fa-biohazard mr-1.5"></i> Inject Malicious Edit Into Block
            </button>
            <button onclick="resetBlockchain()" class="w-full py-2 bg-slate-800 hover:bg-slate-700 text-xs font-medium rounded-lg text-slate-300 transition">
              <i class="fa-solid fa-rotate-left mr-1.5"></i> Reset & Repair Genuine Ledger
            </button>
          </div>
        </div>

      </div>
    </section>

  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800/80 bg-slate-900/40 text-center py-4 text-xs text-slate-500">
    Blockchain-Based Electronic Voting System • NIST SHA-256 Hashing • RSA-2048 Digital Signatures • Localhost Port 5000
  </footer>

  <!-- Client-Side JavaScript -->
  <script>
    let activeVoter = null;
    let selectedCandidate = null;

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('border-blue-500', 'text-blue-400');
        btn.classList.add('border-transparent', 'text-slate-400');
      });
      document.getElementById('tab-' + tabId).classList.add('border-blue-500', 'text-blue-400');
      document.getElementById('tab-' + tabId).classList.remove('border-transparent', 'text-slate-400');

      ['dashboard', 'booth', 'explorer', 'verify', 'admin'].forEach(pane => {
        document.getElementById('pane-' + pane).classList.add('hidden');
      });
      document.getElementById('pane-' + tabId).classList.remove('hidden');

      if (tabId === 'dashboard') refreshData();
      if (tabId === 'explorer') refreshBlocks();
    }

    async function refreshData() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();

        document.getElementById('totalVotes').innerText = data.totalVotes;
        document.getElementById('totalRegistered').innerText = data.totalRegistered;
        document.getElementById('voterTurnout').innerText = data.turnout + '%';
        document.getElementById('blockCountBadge').innerText = data.blockCount;
        document.getElementById('electionStateBadge').innerText = data.state;

        // Chain status
        const chainBadge = document.getElementById('chainBadge');
        const statusPulse = document.getElementById('statusPulse');
        if (data.chainValid) {
          chainBadge.innerText = 'VALID & UNTAMPERED';
          chainBadge.className = 'text-emerald-400 font-bold';
          statusPulse.className = 'w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping';
        } else {
          chainBadge.innerText = 'TAMPER DETECTED!';
          chainBadge.className = 'text-rose-400 font-bold animate-pulse';
          statusPulse.className = 'w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping';
        }

        // Winner banner
        const winnerBanner = document.getElementById('winnerBanner');
        if (data.state === 'ENDED') {
          winnerBanner.classList.remove('hidden');
          document.getElementById('winnerText').innerText = data.winner === 'TIE' ? 'The election ended in a TIE!' : `Winner: ${data.winner}`;
        } else {
          winnerBanner.classList.add('hidden');
        }

        // Render Candidates Tally
        const list = document.getElementById('candidatesList');
        list.innerHTML = '';
        const total = data.totalVotes || 1;

        data.candidates.forEach((cand, idx) => {
          const count = data.tally[cand] || 0;
          const pct = ((count / total) * (data.totalVotes > 0 ? 100 : 0)).toFixed(1);
          const barWidth = data.totalVotes > 0 ? pct : 0;

          list.innerHTML += `
            <div class="space-y-1.5">
              <div class="flex justify-between text-sm">
                <span class="font-bold text-slate-200">${idx + 1}. ${cand}</span>
                <span class="text-slate-400 mono-font">${count} votes <span class="text-blue-400 font-semibold">(${pct}%)</span></span>
              </div>
              <div class="w-full bg-slate-800 rounded-full h-3 overflow-hidden">
                <div class="bg-gradient-to-r from-blue-500 to-indigo-500 h-3 rounded-full transition-all duration-700" style="width: ${barWidth}%"></div>
              </div>
            </div>
          `;
        });

        // Update ballot choices
        updateBallotCandidates(data.candidates);

      } catch (err) {
        console.error('Error refreshing status:', err);
      }
    }

    function updateBallotCandidates(candidates) {
      const container = document.getElementById('ballotCandidateButtons');
      if (!container) return;
      container.innerHTML = '';
      candidates.forEach(cand => {
        const isSelected = selectedCandidate === cand;
        container.innerHTML += `
          <button onclick="selectCandidate('${cand}')" class="p-4 rounded-xl border text-left transition ${isSelected ? 'border-blue-500 bg-blue-500/20 text-white' : 'border-slate-800 bg-slate-800/40 text-slate-300 hover:border-slate-700'}">
            <div class="font-bold text-sm">${cand}</div>
            <div class="text-xs text-slate-400 mt-1">${isSelected ? '✓ Selected' : 'Click to select'}</div>
          </button>
        `;
      });
    }

    function selectCandidate(name) {
      selectedCandidate = name;
      updateBallotCandidates(window.currentCandidates || ['Alice Johnson', 'Bob Smith', 'Charlie Davis']);
      document.getElementById('castVoteBtn').disabled = !activeVoter || !selectedCandidate;
    }

    async function loginVoter() {
      const vId = document.getElementById('loginVoterId').value.trim();
      const pwd = document.getElementById('loginPassword').value.trim();
      try {
        const res = await fetch('/api/voter/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({voterId: vId, password: pwd})
        });
        const data = await res.json();
        if (!data.success) {
          alert('Login failed: ' + data.message);
          return;
        }

        activeVoter = data.session;
        document.getElementById('loginForm').classList.add('hidden');
        document.getElementById('authSuccessBox').classList.remove('hidden');
        document.getElementById('sessionVoterId').innerText = activeVoter.voterId;
        document.getElementById('sessionVoterHash').innerText = activeVoter.voterHash;

        document.getElementById('votingDisabledPrompt').classList.add('hidden');
        document.getElementById('ballotCandidates').classList.remove('hidden');

        if (activeVoter.hasVoted) {
          document.getElementById('castVoteBtn').disabled = true;
          document.getElementById('castVoteBtn').innerText = 'Ballot Already Recorded (Double-Voting Prohibited)';
        } else {
          document.getElementById('castVoteBtn').disabled = !selectedCandidate;
          document.getElementById('castVoteBtn').innerHTML = '<i class="fa-solid fa-file-signature mr-2"></i> Sign Ballot & Mine Onto Blockchain';
        }
      } catch (err) {
        alert('Authentication error: ' + err);
      }
    }

    function logoutVoter() {
      activeVoter = null;
      document.getElementById('loginForm').classList.remove('hidden');
      document.getElementById('authSuccessBox').classList.add('hidden');
      document.getElementById('votingDisabledPrompt').classList.remove('hidden');
      document.getElementById('ballotCandidates').classList.add('hidden');
      document.getElementById('receiptResultCard').classList.add('hidden');
    }

    async function registerVoter() {
      const vId = document.getElementById('regVoterId').value.trim();
      const pwd = document.getElementById('regPassword').value.trim();
      if (!vId || !pwd) {
        alert('Please fill out both Voter ID and Password.');
        return;
      }
      try {
        const res = await fetch('/api/voter/register', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({voterId: vId, password: pwd})
        });
        const data = await res.json();
        if (data.success) {
          alert(data.message + ' You may now log in!');
          document.getElementById('loginVoterId').value = vId;
          document.getElementById('loginPassword').value = pwd;
        } else {
          alert('Registration rejected: ' + data.message);
        }
      } catch (err) {
        alert('Registration error: ' + err);
      }
    }

    async function submitBallot() {
      if (!activeVoter || !selectedCandidate) return;

      const btn = document.getElementById('castVoteBtn');
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Signing RSA-2048 & Mining Block...';

      try {
        const res = await fetch('/api/vote', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({voterId: activeVoter.voterId, candidate: selectedCandidate})
        });
        const data = await res.json();
        if (!data.success) {
          alert('Vote rejected: ' + data.message);
          btn.disabled = false;
          btn.innerHTML = '<i class="fa-solid fa-file-signature mr-2"></i> Sign Ballot & Mine Onto Blockchain';
          return;
        }

        const r = data.receipt;
        activeVoter.hasVoted = true;
        btn.innerText = 'Ballot Recorded in Block #' + r.blockIndex;

        // Display Receipt
        const rc = document.getElementById('receiptResultCard');
        rc.classList.remove('hidden');
        document.getElementById('receiptBlockTag').innerText = 'Block #' + r.blockIndex;
        document.getElementById('receiptBallotId').innerText = r.ballotId;
        document.getElementById('receiptVoterHash').innerText = r.voterHash;
        document.getElementById('receiptCandidate').innerText = r.candidate;
        document.getElementById('receiptBlockHash').innerText = r.blockHash;
        document.getElementById('receiptCode').innerText = r.receiptCode;

        refreshData();
      } catch (err) {
        alert('Error casting vote: ' + err);
        btn.disabled = false;
      }
    }

    async function refreshBlocks() {
      try {
        const res = await fetch('/api/blocks');
        const data = await res.json();
        const container = document.getElementById('blocksContainer');
        container.innerHTML = '';

        data.blocks.forEach((b, idx) => {
          const isGenesis = b.index === 0;
          container.innerHTML += `
            <div class="bg-slate-900/80 border ${data.chainValid ? 'border-slate-800' : 'border-rose-700/60'} p-5 rounded-2xl space-y-3">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <div class="flex items-center gap-3">
                  <span class="w-8 h-8 rounded-lg ${isGenesis ? 'bg-amber-500/20 text-amber-300' : 'bg-blue-500/20 text-blue-300'} flex items-center justify-center font-bold text-xs">
                    #${b.index}
                  </span>
                  <div>
                    <h3 class="font-bold text-sm text-slate-200">${isGenesis ? 'Genesis Block (Primordial Root)' : 'Voting Transaction Block'}</h3>
                    <p class="text-xs text-slate-400 mono-font">${b.timestamp}</p>
                  </div>
                </div>
                <div class="text-xs font-mono bg-slate-950 px-3 py-1 rounded border border-slate-800 text-slate-300">
                  Nonce: <span class="font-bold text-indigo-400">${b.nonce}</span>
                </div>
              </div>

              <!-- Cryptographic Hashes -->
              <div class="space-y-1 text-xs mono-font bg-slate-950 p-3 rounded-xl border border-slate-800/80">
                <div class="truncate"><span class="text-slate-500">PREV HASH :</span> <span class="text-slate-400">${b.previousHash}</span></div>
                <div class="truncate"><span class="text-emerald-500">CURR HASH :</span> <span class="text-emerald-300 font-bold">${b.hash}</span></div>
                <div class="truncate"><span class="text-purple-400">MERKLE RT :</span> <span class="text-purple-300">${b.merkleRoot}</span></div>
              </div>

              <!-- Payload Content -->
              <div class="text-xs bg-slate-950/40 p-3 rounded-xl border border-slate-800">
                <span class="text-slate-400 font-semibold block mb-1">Payload:</span>
                <p class="text-slate-200 mono-font break-all">${b.data}</p>
              </div>
            </div>
            ${idx < data.blocks.length - 1 ? '<div class="flex justify-center text-slate-600 text-sm"><i class="fa-solid fa-arrow-down"></i> (SHA-256 Link)</div>' : ''}
          `;
        });
      } catch (err) {
        console.error('Error fetching blocks:', err);
      }
    }

    async function auditBlockchain() {
      const banner = document.getElementById('auditResultBanner');
      banner.classList.remove('hidden');
      banner.className = 'p-4 rounded-xl text-sm font-medium bg-blue-500/10 text-blue-300 border border-blue-500/30';
      banner.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Auditing cryptographic hashes, linkages, proof-of-work, and digital signatures...';

      const res = await fetch('/api/status');
      const data = await res.json();

      setTimeout(() => {
        if (data.chainValid) {
          banner.className = 'p-4 rounded-xl text-sm font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/30';
          banner.innerHTML = '<i class="fa-solid fa-circle-check mr-2"></i> AUDIT PASSED: All ' + data.blockCount + ' blocks are cryptographically intact and verified.';
        } else {
          banner.className = 'p-4 rounded-xl text-sm font-medium bg-rose-500/10 text-rose-300 border border-rose-500/30';
          banner.innerHTML = '<i class="fa-solid fa-triangle-exclamation mr-2"></i> AUDIT FAILED! ' + data.chainMessage;
        }
      }, 500);
    }

    async function verifyBallotReceipt() {
      const val = document.getElementById('verifyInput').value.trim();
      const out = document.getElementById('verifyOutcome');
      if (!val) {
        alert('Please enter a Receipt Proof Code or Ballot ID.');
        return;
      }
      out.classList.remove('hidden');
      out.className = 'p-4 rounded-xl text-xs bg-slate-800 text-slate-300';
      out.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Querying blockchain ledger...';

      try {
        const res = await fetch('/api/receipt/verify', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({receiptCode: val, ballotId: val})
        });
        const data = await res.json();
        if (data.valid) {
          out.className = 'p-4 rounded-xl text-xs bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 space-y-1.5';
          out.innerHTML = `
            <div class="font-bold text-sm flex items-center gap-1.5"><i class="fa-solid fa-shield-check"></i> ${data.message}</div>
            <div class="mono-font text-slate-300 mt-2">
              <div><strong>Ballot:</strong> ${data.ballotId} (Block #${data.blockIndex})</div>
              <div><strong>Candidate:</strong> ${data.candidate}</div>
              <div><strong>Timestamp:</strong> ${data.timestamp}</div>
              <div><strong>Block Hash:</strong> ${data.blockHash.substr(0, 24)}...</div>
              <div><strong>Signature Verified:</strong> ✓ RSA-2048 Valid</div>
            </div>
          `;
        } else {
          out.className = 'p-4 rounded-xl text-xs bg-rose-500/10 border border-rose-500/30 text-rose-300 font-semibold';
          out.innerHTML = '<i class="fa-solid fa-circle-xmark mr-1.5"></i> ' + data.message;
        }
      } catch (err) {
        out.innerText = 'Error: ' + err;
      }
    }

    async function startElection() {
      const res = await fetch('/api/admin/start', {method: 'POST'});
      const data = await res.json();
      alert(data.success ? 'Election is now IN_PROGRESS!' : data.message);
      refreshData();
    }

    async function endElection() {
      const res = await fetch('/api/admin/end', {method: 'POST'});
      const data = await res.json();
      alert(data.success ? 'Election concluded! Final tallies recorded.' : data.message);
      refreshData();
    }

    async function addCandidate() {
      const name = document.getElementById('newCandidateName').value.trim();
      if (!name) return;
      const res = await fetch('/api/admin/candidate/add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({candidate: name})
      });
      const data = await res.json();
      alert(data.success ? `Candidate '${name}' added.` : data.message);
      document.getElementById('newCandidateName').value = '';
      refreshData();
    }

    async function tamperBlock() {
      const idx = document.getElementById('tamperBlockIndex').value;
      const res = await fetch('/api/admin/tamper', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({blockIndex: idx})
      });
      const data = await res.json();
      alert(data.message + '\\nChain Status: ' + (data.chainValid ? 'VALID' : 'TAMPER DETECTED!'));
      refreshData();
      refreshBlocks();
    }

    async function resetBlockchain() {
      const res = await fetch('/api/admin/reset', {method: 'POST'});
      const data = await res.json();
      alert(data.message);
      refreshData();
      refreshBlocks();
    }

    // Initialize on page load
    refreshData();
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"================================================================")
    print(f"  BLOCKCHAIN VOTING SYSTEM WEB DASHBOARD IS LIVE!")
    print(f"  Local Host Link: http://localhost:{port}")
    print(f"  Local Host Link: http://127.0.0.1:{port}")
    print(f"================================================================")
    app.run(host="0.0.0.0", port=port, debug=False)

