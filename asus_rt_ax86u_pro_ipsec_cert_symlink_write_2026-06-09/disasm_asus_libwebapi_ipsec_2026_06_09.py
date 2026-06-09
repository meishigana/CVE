#!/usr/bin/env python3
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile


DEFAULT_BINARY = "/root/inout/firmware/unpacked/asus/RT-AX86U_PRO_300610237436/_RT-AX86U_PRO_3.0.0.6_102_37436-g5a1fb9f_476-gaed2e_nand_squashfs.pkgtb.extracted/squashfs-root/usr/lib/libwebapi.so"
DEFAULT_OUT = "/root/inout/work/deepdive/asus_rt_ax86u_pro_300610237436_initial_2026_06_09/libwebapi_ipsec_disasm.txt"


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BINARY
    out = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    targets = {
        "gen_server_ipsec_file": (0xC720, 380),
        "upload_server_ipsec_cert_cgi": (0xC89C, 564),
    }

    with open(binary, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        rodata = elf.get_section_by_name(".rodata")
        relplt = elf.get_section_by_name(".rel.plt")
        dynsym = elf.get_section_by_name(".dynsym")
        plt = elf.get_section_by_name(".plt")

        plt_names = {}
        if relplt and dynsym and plt:
            for idx, rel in enumerate(relplt.iter_relocations()):
                sym = dynsym.get_symbol(rel.entry.r_info_sym)
                # ARM PLT[0] is resolver; each following entry is 12 bytes in this binary.
                plt_names[plt["sh_addr"] + 0x14 + idx * 12] = sym.name

        text_data = text.data()
        text_addr = text["sh_addr"]
        rodata_data = rodata.data()
        rodata_addr = rodata["sh_addr"]

    def cstr_at(addr):
        if not (rodata_addr <= addr < rodata_addr + len(rodata_data)):
            return None
        off = addr - rodata_addr
        end = rodata_data.find(b"\0", off)
        if end < 0:
            end = min(len(rodata_data), off + 160)
        data = rodata_data[off:end]
        if not data or any((b < 0x20 or b > 0x7e) and b not in (9,) for b in data):
            return None
        return data.decode("ascii", "replace")

    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    lines = []
    lines.append(f"binary: {binary}")
    lines.append("")

    for name, (addr, size) in targets.items():
        off = addr - text_addr
        blob = text_data[off : off + size]
        lines.append(f"## {name} @ 0x{addr:x}, size {size}")
        for insn in md.disasm(blob, addr):
            note = ""
            if insn.mnemonic == "bl":
                try:
                    tgt = int(insn.op_str[1:], 16) if insn.op_str.startswith("#") else int(insn.op_str, 16)
                    if tgt in plt_names:
                        note = f" ; {plt_names[tgt]}"
                except ValueError:
                    pass
            elif insn.mnemonic == "ldr" and ", [pc" in insn.op_str:
                try:
                    # Literal address is aligned enough for this evidence helper.
                    lit_addr = insn.address + 8 + insn.operands[1].mem.disp
                    lit_off = lit_addr - text_addr
                    if 0 <= lit_off <= len(text_data) - 4:
                        value = int.from_bytes(text_data[lit_off : lit_off + 4], "little")
                        s = cstr_at(value)
                        if s:
                            note = f" ; -> 0x{value:x} \"{s}\""
                except Exception:
                    pass
            lines.append(f"0x{insn.address:08x}: {insn.mnemonic:8s} {insn.op_str}{note}")
        lines.append("")

    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(out)


if __name__ == "__main__":
    main()
