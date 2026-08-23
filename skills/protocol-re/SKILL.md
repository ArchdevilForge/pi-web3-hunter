---
name: protocol-re
description: >-
  Reverse custom or binary network protocols: capture, dissect, document.
  Use for proprietary TCP/UDP, pcap, unknown framing, or Wireshark dissectors.
  Browser HTTP/JS signing and page-side capture → js-reverse.
---

# Protocol Reverse Engineering

浏览器里的 HTTP/签名/JS 触发链走 `js-reverse`。本 skill 只管**自定义帧、二进制、非浏览器流量**。

命令语法查 `tshark -h` / `tcpdump --help` / `man pcap-filter`，不要把手册抄进任务。

## 工作流

### 1. Observe

多抓几段：握手、稳态、断开，各至少一次。

```bash
tshark -i <iface> -w capture.pcap
# 或
tcpdump -i <iface> -s 0 -w capture.pcap host <ip>
```

HTTPS 明文需要用户已有的 MITM/密钥；没有就停在密文，标「未解密」。

必须产出：pcap 路径、端口/对端、样本次数。

### 2. Dissect

对样本做 diff，只保留重复出现的结构：

- magic / 长度字段 / type / 序号 / 校验
- 消息边界（定长、length-prefix、分隔符）
- 状态：谁先发、应答配对

工具：Wireshark Follow Stream、hex diff。解析骨架 → [references/parsers.md](references/parsers.md)。

### 3. Document

填 [references/spec.md](references/spec.md)。每个字段都要能指回 pcap 里的偏移。写不出证据的字段删掉。

### 4. Validate

用 parsers.md 的解析器吃原始 payload，与文档一致才算完成。格式稳定后再写 spec.md 里的 Lua dissector。

## 完成标准

- [ ] 有 pcap（或用户提供的样本），不是口头描述
- [ ] 文档每个字段有样本证据
- [ ] 解析器能 round-trip 至少一条真实消息
- [ ] 浏览器 JS/签名不在本 skill 里做
