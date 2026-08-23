# 协议文档模板 + Wireshark Lua

（从主文件分流。Dissect 出字段后再填。）

```markdown
# <Protocol> Specification

## Overview
目的、谁连谁。

## Transport
- Layer: TCP | UDP
- Port:
- Encryption:

## Header

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | Magic | |
| 4 | 2 | Version | |
| 6 | 2 | Type | |
| 8 | 4 | Length | payload bytes |

## Message types

| Type | Name | Role |
|------|------|------|
| 0x01 | HELLO | |

## State machine
INIT --HELLO--> WAIT_ACK --HELLO_ACK--> CONNECTED --> CLOSE
```

字段从样本 diff 来，不要从模板反推「应该有 version」。

## Lua dissector（格式稳定后再写）

```lua
local proto = Proto("custom", "Custom Protocol")
local f_magic = ProtoField.string("custom.magic", "Magic")
local f_version = ProtoField.uint16("custom.version", "Version")
local f_type = ProtoField.uint16("custom.type", "Type")
local f_length = ProtoField.uint32("custom.length", "Length")
local f_payload = ProtoField.bytes("custom.payload", "Payload")
proto.fields = { f_magic, f_version, f_type, f_length, f_payload }

function proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CUSTOM"
    local subtree = tree:add(proto, buffer())
    subtree:add(f_magic, buffer(0, 4))
    subtree:add(f_version, buffer(4, 2))
    subtree:add(f_type, buffer(6, 2))
    local length = buffer(8, 4):uint()
    subtree:add(f_length, buffer(8, 4))
    if length > 0 then subtree:add(f_payload, buffer(12, length)) end
end

DissectorTable.get("tcp.port"):add(8888, proto)
```
