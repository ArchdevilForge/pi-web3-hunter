# Python 协议解析器代码库

（从主文件移出，按需加载）

### Python Protocol Parser

```python
import struct
from dataclasses import dataclass

@dataclass
class MessageHeader:
    magic: bytes
    version: int
    msg_type: int
    length: int

    @classmethod
    def from_bytes(cls, data: bytes):
        magic, version, msg_type, length = struct.unpack(
            ">4sHHI", data[:12]
        )
        return cls(magic, version, msg_type, length)

def parse_messages(data: bytes):
    offset = 0
    messages = []

    while offset < len(data):
        header = MessageHeader.from_bytes(data[offset:])
        payload = data[offset+12:offset+12+header.length]
        messages.append((header, payload))
        offset += 12 + header.length

    return messages

# Parse TLV structure
def parse_tlv(data: bytes):
    fields = []
    offset = 0

    while offset < len(data):
        field_type = data[offset]
        length = struct.unpack(">H", data[offset+1:offset+3])[0]
        value = data[offset+3:offset+3+length]
        fields.append((field_type, value))
        offset += 3 + length

    return fields
```

### Hex Dump Analysis

```python
def hexdump(data: bytes, width: int = 16):
    """Format binary data as hex dump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.'
            for b in chunk
        )
        lines.append(f'{i:08x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(lines)

# Example output:
# 00000000  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  HTTP/1.1 200 OK.
# 00000010  0a 43 6f 6e 74 65 6e 74  2d 54 79 70 65 3a 20 74  .Content-Type: t
```
