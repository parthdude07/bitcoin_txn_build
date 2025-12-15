
# 🪙 Bitcoin Transaction Builder in Rust

This repository contains my implementation of building a Bitcoin transaction from scratch using Rust, relying only on cryptographic libraries (no high-level Bitcoin SDKs).  
The purpose of this project is to understand how Bitcoin transactions work at a low level.

---

## 🚀 Project Goal

- Manually construct a raw Bitcoin transaction
- Handle serialization, hashing, and signing explicitly
- Understand Bitcoin’s UTXO model and script system
- Avoid high-level Bitcoin libraries and focus on core cryptography

---

## 🧩 What This Project Covers

- Bitcoin transaction inputs and outputs
- Endianness handling (little-endian vs big-endian)
- VarInt encoding
- Double SHA-256 hashing
- ECDSA signing using secp256k1
- Script creation (scriptSig, scriptPubKey)
- Raw transaction hex generation

---

## 🛠️ Tech Stack

- Language: Rust 🦀
- Cryptographic Libraries:
  - secp256k1 (ECDSA signing)
  - sha2 (SHA-256 hashing)
  - ripemd160 (HASH160)
  - hex / bytes (encoding and byte handling)

> No high-level Bitcoin transaction libraries were used intentionally.

---

## 📚 What I Learned From This Project

### 🔐 Bitcoin Internals
- How Bitcoin transactions are structured at the byte level
- How transaction IDs (txid) are generated
- Why Bitcoin uses double SHA-256
- The role of locking and unlocking scripts

### 🧠 Cryptography Concepts
- Practical use of ECDSA signatures
- How private keys authorize spending
- Why secp256k1 is used in Bitcoin
- Public key hashing (HASH160)

### 🧾 UTXO Model
- How inputs reference previous transaction outputs
- Why UTXOs must be fully spent
- How change outputs are created

### ⚙️ Low-Level Engineering
- Importance of correct byte ordering
- How a single wrong byte invalidates a transaction
- Strictness of Bitcoin consensus rules
- Debugging raw transaction hex

---

## 🧪 Why I Built This

Most tutorials rely on high-level abstractions.  
This project was built to:
- Gain a deep understanding of Bitcoin internals
- Learn how wallets manually build transactions
- Practice cryptography-heavy systems programming in Rust

---

## ⚠️ Disclaimer

This project is for educational purposes only.  
Do not use this code with real funds.

---

## 📌 Future Improvements

- SegWit transaction support
- Fee estimation logic
- P2WPKH / P2SH scripts
- Broadcasting transactions via a Bitcoin node
- Full transaction validation

---

## 🧠 Final Takeaway

Bitcoin is conceptually simple but extremely strict in implementation.  
Building a transaction manually highlights the importance of cryptographic correctness.

