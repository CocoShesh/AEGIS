"""Bounded, read-only metadata inspection. Never loads or executes the target."""
import hashlib
import json
import os
import re
import sys
import zipfile

MAX_ARCHIVE_ENTRIES = 20_000
MAX_SAMPLE = 8 * 1024 * 1024


def inspect(path):
    size = os.path.getsize(path)
    h256 = hashlib.sha256()
    h1 = hashlib.sha1()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h256.update(chunk); h1.update(chunk); md5.update(chunk)
    with open(path, "rb") as f:
        head = f.read(4096)
    family, mime, details, gaps = "unknown", "application/octet-stream", {}, []
    if head.startswith(b"MZ"):
        family, mime = "PE executable", "application/vnd.microsoft.portable-executable"
        with open(path, "rb") as f:
            f.seek(0x3c); raw = f.read(4)
            peoff = int.from_bytes(raw, "little") if len(raw) == 4 else 0
            f.seek(peoff); sig = f.read(24)
        if sig.startswith(b"PE\0\0"):
            machine = int.from_bytes(sig[4:6], "little")
            sections = int.from_bytes(sig[6:8], "little")
            characteristics = int.from_bytes(sig[22:24], "little")
            details.update(machine=f"0x{machine:04x}", section_count=sections,
                           dll=bool(characteristics & 0x2000), pe_header="present")
        else:
            details["pe_header"] = "MZ header present; PE signature not found at declared offset"
            gaps.append("PE structure is incomplete or malformed")
    elif head.startswith(b"\x7fELF"):
        family, mime = "ELF executable", "application/x-elf"
        details.update(elf_class={1:"32-bit",2:"64-bit"}.get(head[4],"unknown"),
                       endianness={1:"little",2:"big"}.get(head[5],"unknown"),
                       object_type=int.from_bytes(head[16:18], "little") if len(head) >= 18 and head[5] == 1 else "available in raw header")
    elif head.startswith(b"\x7fMach") or head[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        family, mime = "Mach-O executable", "application/x-mach-binary"
        details["header"] = "Mach-O or universal binary signature detected"
    elif head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        family, mime = "ZIP container", "application/zip"
        try:
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()[:MAX_ARCHIVE_ENTRIES]
                names = [i.filename[:200] for i in infos[:1000]]
                details.update(entry_count=len(zf.infolist()), inspected_entries=len(names),
                               encrypted_entries=sum(bool(i.flag_bits & 1) for i in infos),
                               suspicious_member_names_sampled=sum(bool(re.search(r"(^/|(^|/)\.\.(?:/|$)|^[A-Za-z]:)", n)) for n in names))
                if len(zf.infolist()) > MAX_ARCHIVE_ENTRIES:
                    gaps.append("Archive listing capped at 20,000 entries")
                details["sample_names"] = names[:30]
        except (OSError, zipfile.BadZipFile, RuntimeError):
            gaps.append("ZIP directory could not be safely read")
    elif head.startswith(b"%PDF-"):
        family, mime = "PDF document", "application/pdf"
        details["pdf_header"] = head[:8].decode("ascii", "replace")
    elif head.startswith(b"\x1f\x8b"):
        family, mime = "GZIP archive", "application/gzip"
    elif b"\x00" not in head and head:
        family, mime = "Text or script", "text/plain"
        details["text_bytes_sampled"] = min(size, MAX_SAMPLE)
        gaps.append("Text content was not uploaded to AI or executed; deeper language-specific review is not integrated")
    else:
        gaps.append("Format-specific parser is not integrated; only hashes and header metadata were collected")
    return {"size_bytes": size, "sha256": h256.hexdigest(), "sha1": h1.hexdigest(),
            "md5": md5.hexdigest(), "family": family, "mime": mime,
            "details": details, "limitations": gaps,
            "native_execution": "NEVER_PERFORMED"}


if __name__ == "__main__":
    try:
        result = inspect(sys.argv[1])
        print(json.dumps(result, separators=(",", ":")))
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
