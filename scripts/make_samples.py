"""Generate deterministic synthetic filesystem archives, not vendor firmware."""
import gzip
import io
import struct
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def elf_fixture(hardened=False, bits=64, endian="little", shared=False):
    """Small structurally valid ELF header/tables for metadata tests; not executable code."""
    prefix = "<" if endian == "little" else ">"
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1,1 if endian == "little" else 2,1]) + bytes(9)
    header_size, ph_size = (64,56) if bits == 64 else (52,32)
    headers = [(0x6474e551,6 if hardened else 7,0,0)]  # GNU_STACK
    if hardened:
        headers += [(0x6474e552,4,0,0),(2,6,header_size+ph_size*4,32 if bits == 64 else 16), (3,4,header_size+ph_size*4+(32 if bits == 64 else 16),20)]
    etype = 3 if hardened or shared else 2
    if bits == 64:
        hdr = struct.pack(prefix+"HHIQQQIHHHHHH",etype,62,1,0,header_size,0,0,header_size,ph_size,len(headers),64,0,0)
        ph = b"".join(struct.pack(prefix+"IIQQQQQQ",t,flags,offset,0,0,size,size,8) for t,flags,offset,size in headers)
        dynamic = struct.pack(prefix+"QQQQ",24,0,0,0) if hardened else b""
    else:
        hdr = struct.pack(prefix+"HHIIIIIHHHHHH",etype,40,1,0,header_size,0,0,header_size,ph_size,len(headers),40,0,0)
        ph = b"".join(struct.pack(prefix+"IIIIIIII",t,offset,0,0,size,size,flags,4) for t,flags,offset,size in headers)
        dynamic = struct.pack(prefix+"IIII",24,0,0,0) if hardened else b""
    return ident + hdr + ph + dynamic + (b"/lib/ld-linux.so.2\x00\x00" if hardened else b"")

def contents(version):
    old = version == 1
    return {
        "etc/device.conf": (b"device_name=sample_router\nwifi_password=dummy_wifi_value\n" +
            (b"password=dummy_old_value\ntelnet_enabled=true\nssl_verify=false\ndebug=true\n" if old else b"api_key=dummy_new_value\ntelnet_enabled=false\nssl_verify=true\ndebug=false\n")),
        "etc/ssh/sshd_config": b"PermitRootLogin yes\nPasswordAuthentication yes\n" if old else b"PermitRootLogin no\nPasswordAuthentication no\n",
        "usr/lib/version.txt": b"OpenSSL 1.0.1f\nBusyBox v1.30.1\ndnsmasq-2.77\n" if old else b"OpenSSL 1.0.1g\nBusyBox v1.36.1\ndnsmasq-2.78\n",
        "usr/bin/sample.elf": elf_fixture(hardened=not old),
        "etc/passwd": b"root::0:0:root:/root:/bin/sh\n" if old else b"root:x:0:0:root:/root:/bin/sh\n",
        ("etc/old.conf" if old else "etc/new.conf"): b"setting=enabled\n",
    }

def generate():
    samples = ROOT / "samples"; samples.mkdir(exist_ok=True)
    with zipfile.ZipFile(samples / "firmware_v1.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for name,data in contents(1).items():
            info = zipfile.ZipInfo(name, (2024,1,1,0,0,0));info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system=3;info.external_attr=(0o100644 << 16)
            archive.writestr(info,data)
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name,data in contents(2).items():
            info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;info.mtime=0
            archive.addfile(info,io.BytesIO(data))
    (samples / "firmware_v2.tar.gz").write_bytes(gzip.compress(buffer.getvalue(),mtime=0))
    print("Created firmware_v1.zip and firmware_v2.tar.gz (synthetic test archives).")

if __name__ == "__main__": generate()
