# hunt — Pi Web3 Security Hunter

Authorized Web3 & DeFi security hunting plugin for **Pi**. Built with **[Effect-TS](https://www.effect.website/)** from first principles, following the **KISS (Keep It Simple, Stupid)** philosophy.

Both in the terminal and in Pi TUI, everything uses the same single word: **`hunt`**.

---

## 🎯 极简统一指令 (KISS Usage)

### 1. 终端命令行 (Terminal CLI: `hunt`)

```bash
# 启动挖洞 (分析当前目录)
hunt

# 猎取链上目标合约
hunt 0x1234567890123456789012345678901234567890 -c 1

# 辅助指令
hunt status <run-id>    # 查看进度与状态
hunt report <run-id>    # 生成漏洞报告
hunt verify <run-id>    # 验证证据哈希链
hunt check              # 工具链环境体检
```

---

### 2. Pi 内部交互 (TUI Slash Command: `/hunt`)

```text
/hunt                  # 当前目录开始挖洞
/hunt 0x123... -c 1    # 链上合约挖洞
/hunt -m list          # 切换为批量队列模式
/hunt -m loop          # 切换为持续 Fuzz 变异循环
/hunt status           # 查看状态
/hunt report           # 生成报告
/hunt check            # 扫描器检查
```

---

## ⚡ 核心能力与第一性原理

- **Anti-Bamboozle 独立审查 (Detached Auditor)**：彻底消除 Agent 自我欺骗，所有声称复现的漏洞必须通过独立的 7 门禁（7-Gate）Fork 回放与资金/状态差（State Delta）断言。
- **全套 Effect-TS 原生架构**：
  - `MultiChainService`：内置 9 大主流 EVM 链免密 Public RPC 映射。
  - `ForkService`：基于 Effect `Scope` 的 Anvil 零残留生命周期管理。
  - `ScannerService`：一级支持 `Forge`, `Slither`, `Aderyn`, `Halmos`, `Echidna`, `Medusa`, `Cast`。
  - `PoCService`：自动化脚手架生成标准 Foundry Exploit，强制拦截 `vm.store` 等存储作弊。
  - `LedgerService`：基于 SHA-256 哈希链的防篡改证据账本。

---

## 🛠️ 安装与全局生效

```bash
npm install
npm link
pi install /absolute/path/to/pi-web3-hunter
```
