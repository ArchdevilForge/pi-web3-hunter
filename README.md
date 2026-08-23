<div align="center">

# 🎯 hunt — Pi Web3 Security Hunter

**Autonomous, Evidence-Backed Web3 & DeFi Vulnerability Hunting Engine**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node: >=20](https://img.shields.io/badge/Node.js-%3E=20-blue.svg)](https://nodejs.org)
[![TypeScript: 5.9](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org)
[![Powered by Effect-TS](https://img.shields.io/badge/Powered%20by-Effect--TS-purple.svg)](https://www.effect.website)
[![Tests: Passing](https://img.shields.io/badge/Tests-5%2F5%20Passed-brightgreen.svg)]()

*KISS Philosophy · Anti-Bamboozle Detached Auditor · Zero-Cheat PoC Synthesizer · Cryptographic Ledger*

</div>

---

## 🌟 Why `hunt`?

In Web3 bug bounty (Immunefi, Cantina, Code4rena, Sherlock), **theoretical alerts and AI hallucinations have zero financial value**. A vulnerability is only real when backed by a deterministic, reproducible, executable **Proof of Concept (PoC)** on a pinned block.

`hunt` is built from **first principles** with **[Effect-TS](https://www.effect.website/)** to bridge the gap between AI reasoning and deterministic blockchain validation:

1. **Anti-Bamboozle Detached Auditor**:
   - The implementing AI agent is **never trusted** to certify its own claims.
   - An independent, isolated subprocess re-executes the PoC on a clean local Anvil fork to verify all **7 Validation Gates** before any finding can be confirmed.
2. **Strict State Delta & Anti-Cheat PoC Engine**:
   - Findings require an executable Foundry test (`testExploit()`) demonstrating measurable economic gain ($\Delta\text{Balance} > 0$) or privilege takeover.
   - Prohibits `vm.store` cheatcode bypasses: exploits must use realistic transactions.
3. **Full Effect-TS Service Architecture**:
   - Zero-leak resource management via `Scope` and `Effect.acquireRelease` (auto-teardown of Anvil forks and temporary sandboxes).
   - Pure typed errors (`HuntError`), structured concurrency (`Fibers`), and schema validation.
4. **Built-in Multi-Chain Resolution**:
   - Zero-config public RPC directory for 9 major EVM networks (Ethereum, Arbitrum, Base, Optimism, Polygon, BSC, Avalanche, Linea, Scroll).
5. **Cryptographic SHA-256 Hash Chain**:
   - Append-only event-sourcing ledger verifying that every command output, finding, and report is cryptographically linked and tamper-proof.

---

## 🏗️ Architecture

```mermaid
graph TD
    subgraph UI & Entry
        CLI["CLI: hunt [target]"]
        TUI["Pi TUI: /hunt [target]"]
    end

    subgraph Pi Agent (Cognitive Layer)
        XRAY["X-Ray Threat Modeling"]
        INVAR["Invariant & Hypothesis Synthesis"]
        POC_GEN["Foundry Exploit PoC Drafting"]
    end

    subgraph Effect-TS Services (Deterministic Muscle & Arbiter)
        MULTI["MultiChainService (9 EVM Networks & Public RPCs)"]
        FORK["ForkService (Scoped Ephemeral Anvil Lifecycle)"]
        SCAN["ScannerService (Forge, Slither, Aderyn, Halmos, Echidna, Medusa)"]
        POC["PoCService (Anti-Cheat & State Delta Verification)"]
        AUDIT["DetachedAuditorService (Isolated 7-Gate Arbiter)"]
        LEDGER["LedgerService (SHA-256 Hash-Chained Event Sourcing)"]
    end

    CLI & TUI --> Pi Agent
    Pi Agent <--> MULTI & FORK & SCAN & POC & AUDIT & LEDGER
    AUDIT --> LEDGER
    LEDGER --> REPORT["Verified Bounty Report (Immunefi / Cantina)"]
```

---

## ⚡ Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/ArchdevilForge/pi-web3-hunter.git
cd pi-web3-hunter

# Install dependencies and build
npm install
npm run build

# Link globally for terminal CLI
npm link

# Install into Pi coding agent
pi install $(pwd)
```

### 2. Scanner Prerequisites

For full static and dynamic scanning capabilities, install the underlying toolchains:

| Tool | Category | Installation / Source |
|---|---|---|
| **Foundry** (`forge`, `cast`, `anvil`) | Core EVM Dev & Testing | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| **Slither** | Static Analysis | `pip3 install slither-analyzer` |
| **Aderyn** | Fast Rust Static Analysis | `cargo install aderyn` |
| **Halmos** | Symbolic Execution Formal Verifier | `pip3 install halmos` |
| **Echidna** / **Medusa** | Invariant Fuzzing | [Crytic GitHub](https://github.com/crytic) |

Check environment health anytime with:
```bash
hunt check
```

---

## 🎯 Usage (KISS Philosophy)

Both in the terminal and in Pi TUI, everything uses the same single word: **`hunt`**.

### In Pi Interactive TUI (`/hunt`)

```text
# 1. Hunt current workspace repository (Default Goal mode)
/hunt

# 2. Hunt a deployed smart contract (Auto-resolves Public RPC & Fork)
/hunt 0x1234567890123456789012345678901234567890 -c 1

# 3. Choose hunting mode (goal / list / loop)
/hunt -m list       # Serial queue for triaging multiple attack vectors
/hunt -m loop       # Continuous invariant fuzzing until plateau

# 4. Status, Reports & Verification
/hunt status        # Display live progress and confirmed findings
/hunt report        # Build and export markdown audit report
/hunt verify        # Verify cryptographic evidence ledger integrity
/hunt check         # Preflight tool availability check
```

### In Terminal CLI (`hunt` or `pwh`)

```bash
# Start a hunt on current directory or contract
hunt [target] [-c <chain-id>] [-m <goal|list|loop>]

# Subcommands
hunt status <run-id>
hunt report <run-id>
hunt verify <run-id>
hunt check
```

---

## 🛡️ The 7 Validation Gates

Every confirmed vulnerability recorded in the evidence ledger must pass all 7 criteria:

| Gate | Requirement | Proof Mechanism |
|---|---|---|
| `reproduced` | Vulnerability is deterministically reproducible | Foundry PoC test passes (`PASS`) on pinned fork block |
| `impactInScope` | Asset/contract is within program scope | Scope attestation manifest |
| `rootCauseInScope` | Bug originates in audited code (not 3rd-party) | AST & source location mapping |
| `realisticAttacker` | Exploitable without owner/privileged private keys | Transaction sequence uses permissionless caller |
| `notKnownOrIntended` | Not documented, acknowledged, or intended | Protocol docs & specification check |
| `impactDemonstrated` | Concrete asset loss or control compromise | Measured State Delta ($\Delta\text{Balance} > 0$) |
| `pinnedAndRepeatable` | Fully reproducible by third-party triagers | Pinned commit, chain ID, and fork block number |

---

## 🌐 Supported Multi-Chain Networks

Out-of-the-box support for zero-config public RPCs and explorers:

| Chain ID | Network | Default Public RPCs |
|:---:|---|---|
| `1` | Ethereum Mainnet | `https://eth.llamarpc.com`, `https://cloudflare-eth.com` |
| `10` | Optimism | `https://mainnet.optimism.io`, `https://optimism.llamarpc.com` |
| `56` | BNB Smart Chain | `https://bsc-dataseed.binance.org`, `https://bsc.llamarpc.com` |
| `137` | Polygon | `https://polygon-rpc.com`, `https://polygon.llamarpc.com` |
| `8453` | Base | `https://mainnet.base.org`, `https://base.llamarpc.com` |
| `42161` | Arbitrum One | `https://arb1.arbitrum.io/rpc`, `https://arbitrum.llamarpc.com` |
| `43114` | Avalanche C-Chain | `https://api.avax.network/ext/bc/C/rpc` |
| `59144` | Linea | `https://rpc.linea.build` |
| `534352` | Scroll | `https://rpc.scroll.io` |

*To use custom/private RPCs, set `WEB3_HUNTER_RPC_URL` or `ETH_RPC_URL`.*

---

## 🧪 Development & Testing

```bash
# Run type checking
npm run check

# Run full test suite
npm run test

# Build production bundle
npm run build
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
Built with ❤️ for the Web3 security and bug bounty research community.
