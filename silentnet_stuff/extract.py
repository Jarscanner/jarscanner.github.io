import struct
import zlib
from pathlib import Path

png_path = Path("engine.png")
data = png_path.read_bytes()

PNG_SIG = b"\x89PNG\r\n\x1a\n"

if not data.startswith(PNG_SIG):
    raise ValueError("Not a valid PNG")

pos = 8

while pos + 8 <= len(data): 
    length = struct.unpack(">I", data[pos:pos+4])[0]
    chunk_type = data[pos+4:pos+8]
    chunk_data = data[pos+8:pos+8+length]

    print(chunk_type.decode(errors="replace"), length)

    if chunk_type == b"hIds":
        print("Found hIds chunk")

        payload = zlib.decompress(chunk_data)

        Path("payload.zip").write_bytes(payload)

        print(f"Wrote {len(payload)} bytes to payload.zip")
        break

    pos += 12 + length
else:
    print("No hIds chunk found")
