"""
Format-specific binary parsers for ELF, PE, and Mach-O executables and libraries.

Pure-Python implementation with zero external dependencies (no Ghidra/radare2 needed).
Gracefully handles malformed, truncated, or stripped binaries.
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ParsedBinaryInfo:
    """Metadata extracted from a parsed binary file."""
    format: str                         # "ELF" | "PE" | "Mach-O" | "RawBinary"
    architecture: str = "unknown"       # e.g. "x86_64", "ARM64", "x86"
    is_64bit: bool = True
    endian: str = "little"              # "little" | "big"
    imported_libraries: List[str] = field(default_factory=list)
    symbols: Set[str] = field(default_factory=set)
    strings: List[str] = field(default_factory=list)
    is_stripped: bool = False
    errors: List[str] = field(default_factory=list)


def parse_binary(file_path: Path, max_strings: int = 5000) -> ParsedBinaryInfo:
    """
    Detect format and parse an executable or library binary file.
    Falls back to raw string extraction if format is unknown or corrupted.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
    except Exception as exc:
        info = ParsedBinaryInfo(format="Unknown")
        info.errors.append(f"Cannot read file: {exc}")
        return info

    if len(header) < 4:
        return ParsedBinaryInfo(format="Unknown", errors=["File too small"])

    # Detect Magic
    if header.startswith(b"\x7fELF"):
        return parse_elf(file_path, max_strings)
    elif header.startswith(b"MZ"):
        return parse_pe(file_path, max_strings)
    elif header[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        return parse_macho(file_path, max_strings)
    else:
        # Fallback raw binary inspection
        strings = extract_strings(file_path, max_count=max_strings)
        return ParsedBinaryInfo(
            format="RawBinary",
            strings=strings,
            symbols=set(s for s in strings if re.match(r"^[A-Za-z0-9_]{3,64}$", s)),
        )


def extract_strings(file_path: Path, min_len: int = 4, max_count: int = 5000) -> List[str]:
    """Extract printable ASCII and UTF-16LE strings from binary bytes."""
    found: List[str] = []
    seen: Set[str] = set()

    try:
        with open(file_path, "rb") as f:
            data = f.read(10 * 1024 * 1024)  # Read up to 10MB
    except Exception:
        return []

    # ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for match in ascii_pattern.finditer(data):
        try:
            s = match.group().decode("ascii", errors="ignore").strip()
            if s and s not in seen:
                seen.add(s)
                found.append(s)
                if len(found) >= max_count:
                    return found
        except Exception:
            pass

    # UTF-16LE strings
    utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}")
    for match in utf16_pattern.finditer(data):
        try:
            s = match.group().decode("utf-16le", errors="ignore").strip()
            if s and s not in seen:
                seen.add(s)
                found.append(s)
                if len(found) >= max_count:
                    return found
        except Exception:
            pass

    return found


# ─────────────────────────────────────────────────────────────────────────────
# ELF Parser (Linux / BSD / Android)
# ─────────────────────────────────────────────────────────────────────────────

ELF_MACHINES = {
    0x03: "x86",
    0x3E: "x86_64",
    0x28: "ARM",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}


def parse_elf(file_path: Path, max_strings: int = 5000) -> ParsedBinaryInfo:
    """Parse an ELF binary to extract symbols, dependencies, and strings."""
    info = ParsedBinaryInfo(format="ELF")

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 52:
            info.errors.append("Truncated ELF header")
            return info

        ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = data[5]   # 1 = LE, 2 = BE

        info.is_64bit = (ei_class == 2)
        endian = "<" if ei_data == 1 else ">"
        info.endian = "little" if ei_data == 1 else "big"

        # Read machine
        e_machine = struct.unpack_from(f"{endian}H", data, 18)[0]
        info.architecture = ELF_MACHINES.get(e_machine, f"Machine(0x{e_machine:x})")

        # Section header table offset & entries
        if info.is_64bit:
            if len(data) < 64:
                info.errors.append("Truncated 64-bit ELF header")
                return info
            e_shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", data, 58)[0]
            e_shnum = struct.unpack_from(f"{endian}H", data, 60)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", data, 62)[0]
        else:
            e_shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
            e_shentsize = struct.unpack_from(f"{endian}H", data, 46)[0]
            e_shnum = struct.unpack_from(f"{endian}H", data, 48)[0]
            e_shstrndx = struct.unpack_from(f"{endian}H", data, 50)[0]

        # Check section table bounds
        if e_shoff == 0 or e_shnum == 0 or e_shoff >= len(data):
            info.is_stripped = True
            info.strings = extract_strings(file_path, max_count=max_strings)
            info.symbols = set(s for s in info.strings if re.match(r"^[A-Za-z0-9_]{3,64}$", s))
            return info

        # Parse section headers
        sections = []
        for i in range(e_shnum):
            offset = e_shoff + i * e_shentsize
            if offset + e_shentsize > len(data):
                break

            if info.is_64bit:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
                    struct.unpack_from(f"{endian}IIQQQQIIQQ", data, offset)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
                    struct.unpack_from(f"{endian}IIIIIIIIII", data, offset)

            sections.append({
                "name_idx": sh_name,
                "type": sh_type,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "entsize": sh_entsize,
                "name": "",
            })

        # Resolve section names via shstrtab
        if e_shstrndx < len(sections):
            shstr = sections[e_shstrndx]
            shstr_data = data[shstr["offset"]: shstr["offset"] + shstr["size"]]
            for sec in sections:
                idx = sec["name_idx"]
                if idx < len(shstr_data):
                    end = shstr_data.find(b"\x00", idx)
                    if end != -1:
                        sec["name"] = shstr_data[idx:end].decode("ascii", errors="ignore")

        # Parse symbol tables (.dynsym, .symtab)
        sym_tables = [s for s in sections if s["type"] in (2, 11) or s["name"] in (".dynsym", ".symtab")]
        if not sym_tables:
            info.is_stripped = True

        for sym_sec in sym_tables:
            link_idx = sym_sec["link"]
            if link_idx >= len(sections):
                continue
            strtab_sec = sections[link_idx]
            str_data = data[strtab_sec["offset"]: strtab_sec["offset"] + strtab_sec["size"]]

            entsize = sym_sec["entsize"] or (24 if info.is_64bit else 16)
            num_symbols = sym_sec["size"] // entsize

            for sym_i in range(num_symbols):
                sym_off = sym_sec["offset"] + sym_i * entsize
                if sym_off + entsize > len(data):
                    break

                st_name = struct.unpack_from(f"{endian}I", data, sym_off)[0]
                if st_name < len(str_data):
                    end = str_data.find(b"\x00", st_name)
                    if end != -1:
                        name = str_data[st_name:end].decode("ascii", errors="ignore").strip()
                        if name:
                            info.symbols.add(name)

        # Parse .dynamic section to extract DT_NEEDED libraries
        dynamic_secs = [s for s in sections if s["name"] == ".dynamic" or s["type"] == 6]
        for dyn_sec in dynamic_secs:
            link_idx = dyn_sec["link"]
            if link_idx < len(sections):
                str_data = data[sections[link_idx]["offset"]: sections[link_idx]["offset"] + sections[link_idx]["size"]]
                dyn_entsize = 16 if info.is_64bit else 8
                num_dyn = dyn_sec["size"] // dyn_entsize
                for dyn_i in range(num_dyn):
                    dyn_off = dyn_sec["offset"] + dyn_i * dyn_entsize
                    if dyn_off + dyn_entsize > len(data):
                        break
                    if info.is_64bit:
                        d_tag, d_val = struct.unpack_from(f"{endian}qQ", data, dyn_off)
                    else:
                        d_tag, d_val = struct.unpack_from(f"{endian}iI", data, dyn_off)

                    if d_tag == 1:  # DT_NEEDED
                        if d_val < len(str_data):
                            end = str_data.find(b"\x00", d_val)
                            if end != -1:
                                lib = str_data[d_val:end].decode("ascii", errors="ignore").strip()
                                if lib:
                                    info.imported_libraries.append(lib)

        # Extract embedded strings
        info.strings = extract_strings(file_path, max_count=max_strings)

    except Exception as exc:
        logger.debug("ELF parser error on %s: %s", file_path, exc)
        info.errors.append(f"ELF parse error: {exc}")
        if not info.strings:
            info.strings = extract_strings(file_path, max_count=max_strings)

    return info


# ─────────────────────────────────────────────────────────────────────────────
# PE Parser (Windows .exe / .dll / .sys)
# ─────────────────────────────────────────────────────────────────────────────

def parse_pe(file_path: Path, max_strings: int = 5000) -> ParsedBinaryInfo:
    """Parse a PE (Portable Executable) binary to extract imports, exports, and strings."""
    info = ParsedBinaryInfo(format="PE")

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 64:
            info.errors.append("Truncated DOS header")
            return info

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            info.errors.append("Invalid e_lfanew pointer")
            return info

        if data[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
            info.errors.append("Missing PE signature")
            return info

        # COFF File Header
        coff_offset = e_lfanew + 4
        machine, num_sections, _, _, _, size_opt_header, _ = struct.unpack_from("<HHIIIHH", data, coff_offset)

        arch_map = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "ARM64"}
        info.architecture = arch_map.get(machine, f"Machine(0x{machine:x})")

        opt_offset = coff_offset + 20
        if opt_offset + size_opt_header > len(data):
            info.errors.append("Truncated Optional Header")
            return info

        opt_magic = struct.unpack_from("<H", data, opt_offset)[0]
        info.is_64bit = (opt_magic == 0x20B)

        # Section headers location
        sec_headers_offset = opt_offset + size_opt_header

        # Parse Section Headers
        sections = []
        for i in range(num_sections):
            sec_off = sec_headers_offset + i * 40
            if sec_off + 40 > len(data):
                break
            name_raw = data[sec_off: sec_off + 8].rstrip(b"\x00")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec_off + 8)
            sections.append({
                "name": name_raw.decode("ascii", errors="ignore"),
                "vaddr": vaddr,
                "vsize": vsize,
                "raw_ptr": raw_ptr,
                "raw_size": raw_size,
            })

        def rva_to_offset(rva: int) -> Optional[int]:
            for s in sections:
                if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["raw_size"]):
                    return s["raw_ptr"] + (rva - s["vaddr"])
            return None

        # Data directories
        dir_offset = opt_offset + (112 if info.is_64bit else 96)
        if dir_offset + 16 <= len(data):
            # Export Table (Index 0)
            export_rva, export_size = struct.unpack_from("<II", data, dir_offset)
            if export_rva:
                exp_off = rva_to_offset(export_rva)
                if exp_off and exp_off + 40 <= len(data):
                    num_names, names_rva = struct.unpack_from("<II", data, exp_off + 24)
                    names_off = rva_to_offset(names_rva)
                    if names_off:
                        for n_i in range(min(num_names, 2000)):
                            ptr = struct.unpack_from("<I", data, names_off + n_i * 4)[0]
                            str_off = rva_to_offset(ptr)
                            if str_off and str_off < len(data):
                                end = data.find(b"\x00", str_off)
                                if end != -1:
                                    sym_name = data[str_off:end].decode("ascii", errors="ignore").strip()
                                    if sym_name:
                                        info.symbols.add(sym_name)

            # Import Table (Index 1)
            import_rva, import_size = struct.unpack_from("<II", data, dir_offset + 8)
            if import_rva:
                imp_off = rva_to_offset(import_rva)
                if imp_off:
                    while imp_off + 20 <= len(data):
                        orig_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, imp_off)
                        if orig_thunk == 0 and first_thunk == 0:
                            break

                        dll_off = rva_to_offset(name_rva)
                        if dll_off:
                            end = data.find(b"\x00", dll_off)
                            if end != -1:
                                dll_name = data[dll_off:end].decode("ascii", errors="ignore").strip()
                                if dll_name:
                                    info.imported_libraries.append(dll_name)

                        # Follow thunk array
                        thunk_rva = orig_thunk or first_thunk
                        thunk_off = rva_to_offset(thunk_rva)
                        step = 8 if info.is_64bit else 4
                        ordinal_mask = 0x8000000000000000 if info.is_64bit else 0x80000000

                        while thunk_off and thunk_off + step <= len(data):
                            val = struct.unpack_from("<Q" if info.is_64bit else "<I", data, thunk_off)[0]
                            if val == 0:
                                break
                            if not (val & ordinal_mask):
                                # Import by name (hint + name)
                                hint_off = rva_to_offset(val)
                                if hint_off and hint_off + 2 < len(data):
                                    end = data.find(b"\x00", hint_off + 2)
                                    if end != -1:
                                        func_name = data[hint_off + 2:end].decode("ascii", errors="ignore").strip()
                                        if func_name:
                                            info.symbols.add(func_name)
                            thunk_off += step

                        imp_off += 20

        # Extract embedded strings
        info.strings = extract_strings(file_path, max_count=max_strings)

    except Exception as exc:
        logger.debug("PE parser error on %s: %s", file_path, exc)
        info.errors.append(f"PE parse error: {exc}")
        if not info.strings:
            info.strings = extract_strings(file_path, max_count=max_strings)

    return info


# ─────────────────────────────────────────────────────────────────────────────
# Mach-O Parser (macOS / iOS / Darwin)
# ─────────────────────────────────────────────────────────────────────────────

def parse_macho(file_path: Path, max_strings: int = 5000) -> ParsedBinaryInfo:
    """Parse a Mach-O binary to extract symbols and strings."""
    info = ParsedBinaryInfo(format="Mach-O")

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 32:
            info.errors.append("Truncated Mach-O header")
            return info

        magic = struct.unpack(">I", data[:4])[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF):
            endian = ">"
        else:
            endian = "<"

        magic_val = struct.unpack(f"{endian}I", data[:4])[0]
        info.is_64bit = (magic_val == 0xFEEDFACF)

        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            f"{endian}IIIIII", data, 4
        )

        offset = 32 if info.is_64bit else 28
        for _ in range(ncmds):
            if offset + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(f"{endian}II", data, offset)
            if cmd == 0x2:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from(f"{endian}IIII", data, offset + 8)
                str_data = data[stroff: stroff + strsize]
                nlist_size = 16 if info.is_64bit else 12

                for s_i in range(min(nsyms, 5000)):
                    n_off = symoff + s_i * nlist_size
                    if n_off + nlist_size > len(data):
                        break
                    n_strx = struct.unpack_from(f"{endian}I", data, n_off)[0]
                    if n_strx < len(str_data):
                        end = str_data.find(b"\x00", n_strx)
                        if end != -1:
                            name = str_data[n_strx:end].decode("ascii", errors="ignore").lstrip("_").strip()
                            if name:
                                info.symbols.add(name)
            elif cmd == 0xC:  # LC_LOAD_DYLIB
                dylib_str_offset = struct.unpack_from(f"{endian}I", data, offset + 8)[0]
                if offset + dylib_str_offset < len(data):
                    end = data.find(b"\x00", offset + dylib_str_offset)
                    if end != -1:
                        dylib = data[offset + dylib_str_offset:end].decode("ascii", errors="ignore").strip()
                        if dylib:
                            info.imported_libraries.append(dylib)

            offset += cmdsize

        info.strings = extract_strings(file_path, max_count=max_strings)

    except Exception as exc:
        logger.debug("Mach-O parser error on %s: %s", file_path, exc)
        info.errors.append(f"Mach-O parse error: {exc}")
        if not info.strings:
            info.strings = extract_strings(file_path, max_count=max_strings)

    return info
