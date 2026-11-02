"""Inspect ELF metadata without executing or dynamically loading a binary."""
import io
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from scanner import finding

def analyse_elf(data, path):
    elf = ELFFile(io.BytesIO(data))
    if elf.num_segments() > 4096 or elf.num_sections() > 8192: raise ValueError("ELF table limit")
    segments = list(elf.iter_segments())
    stack = next((s for s in segments if s["p_type"] == "PT_GNU_STACK"), None)
    nx = "unknown" if stack is None else "disabled" if stack["p_flags"] & 1 else "enabled"
    has_relro = any(s["p_type"] == "PT_GNU_RELRO" for s in segments)
    bind_now, pie_flag = False, False
    for segment in segments:
        if segment["p_type"] == "PT_DYNAMIC":
            if segment["p_filesz"] > 4 * 1024 * 1024: raise ValueError("ELF dynamic table limit")
            # Read numeric dynamic entries; no string table is needed for hardening flags.
            offset, length = segment["p_offset"], segment["p_filesz"]
            if offset + length > len(data): raise ValueError("Truncated ELF dynamic table")
            format = ("<" if elf.little_endian else ">") + ("QQ" if elf.elfclass == 64 else "II")
            size = struct.calcsize(format)
            if length % size: raise ValueError("Misaligned ELF dynamic table")
            for start in range(offset, offset + length, size):
                tag, value = struct.unpack_from(format, data, start)
                if tag == 0: break
                bind_now |= tag == 24 or (tag == 30 and bool(value & 8)) or (tag == 0x6ffffffb and bool(value & 1))
                pie_flag |= tag == 0x6ffffffb and bool(value & 0x08000000)
    typ = elf["e_type"]
    executable = typ == "ET_EXEC" or any(s["p_type"] == "PT_INTERP" for s in segments) or pie_flag
    pie = "enabled" if typ == "ET_DYN" and executable else "disabled" if typ == "ET_EXEC" else "not_applicable"
    symbols, symbol_tables = set(), 0
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            symbol_tables += 1
            if section.num_symbols() > 200000: raise ValueError("ELF symbol limit")
            for symbol in section.iter_symbols():
                name = symbol.name
                if name in {"__stack_chk_fail", "__stack_chk_guard"} or name.endswith("_chk"): symbols.add(name)
    canary = "detected" if symbols & {"__stack_chk_fail", "__stack_chk_guard"} else "not_detected" if symbol_tables else "unknown"
    fortify = "detected" if any(s.endswith("_chk") for s in symbols) else "not_detected" if symbol_tables else "unknown"
    relro = "full" if has_relro and bind_now else "partial" if has_relro else "none"
    result = {"filename": path, "class": elf.elfclass, "endian": "little" if elf.little_endian else "big",
        "machine": elf["e_machine"], "type": typ, "nx": nx, "pie": pie, "relro": relro,
        "stack_canary": canary, "fortify": fortify, "status": "analysed"}
    found = []
    rules = [
        (nx == "disabled", "ELF-NX", "Executable stack requested", "High", "PT_GNU_STACK has the execute flag.", "Link with a non-executable stack where supported."),
        (pie == "disabled", "ELF-PIE", "Executable without PIE", "Medium", "The executable uses ET_EXEC rather than PIE.", "Build supported executables with -fPIE and -pie."),
        (executable and relro != "full", "ELF-RELRO", "Full RELRO not detected", "Medium", "GNU_RELRO and immediate binding were not both present.", "Link supported programs with -Wl,-z,relro,-z,now."),
        (executable and canary == "not_detected", "ELF-CANARY", "Stack canary symbol not detected", "Low", "No recognized stack-check symbol was found; this does not prove absence of protection.", "Review compiler hardening and stack protection."),
    ]
    for condition, rule, title, severity, detail, remedy in rules:
        if condition: found.append(finding(rule, title, path, severity, detail, remedy, category="ELF"))
    return result, found
