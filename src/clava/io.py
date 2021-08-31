"""
Disassemble and parse portable executable (PE) files.
"""
from pathlib import Path
from collections import namedtuple
from typing import List, Tuple

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsInsn

from clava.models import Sample, Label, Instruction

# (mnemomic, raw instruction bytes) e.g. ('PUSH', b"0d1d")
InstructionData = Tuple[str, bytearray]


# A sample's disassembly is the set of all its instructions.
Disassembly = Tuple[int, List[Instruction]]  # (arch, instructions)


def _decode_instruction(instruction: CsInsn) -> Instruction:
    """
    Decode instruction and preserve raw instruction bytes.
    """
    return Instruction(instruction.mnemonic, instruction.bytes)


def disassembleX(filepath: Path, decode=_decode_instruction) -> Sample:
    """
    Disassemble an input binary.

    NOTE: Disassembling only supports valid Portable Executable (PE) files.

    Args:
        filepath: Path to the input binary.
        decode: Function that decodes the instruction (`CsInsn`) thats returned
                during disassembling through Capstone.

    Raises:
        pefile.PEFormatError: If the binary is not a valid PE file.
        ValueError: Raised when the binary has no code section, or if the
                    section could not be decoded (e.g., binary is obfuscated
                    or encrypted).


    Returns:
        A Sample instance with the disassembled code and metadata.

    """
    pe = pefile.PE(str(filepath))

    entrypoint_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(entrypoint_address)

    if not code_section:
        raise ValueError(
            "No valid code section found in file: " + filepath.name)

    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    arch = _determine_architecture(pe)
    md = Cs(CS_ARCH_X86, arch)

    # Disassemble the input binary
    # NOTE: We skip the INT3 debug instruction. However, I can not remember
    #       why we actually skip INT3, as it could be an interesting instr
    #       used by malware (e.g., for anti-debug checks).
    instructions = [
        decode(instr)
        for instr in md.disasm(code_dump, code_addr)
        if instr.mnemonic != "int3"
    ]

    # We assume the input sample to be malicious (i.e., malware), as this is
    # the use case for clava / yara rules.
    label = Label.MALICIOUS

    return Sample(
        filename=filepath.name,
        filesize=filepath.stat().st_size,
        architecture=arch,
        code=instructions,
        label=label
    )


def disassemble(filepath, decode=_decode_instruction) -> Disassembly:
    """
    Given a PE file, disassemble it and return the decoded instructions.
    """
    pe = pefile.PE(filepath)
    entrypoint_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(entrypoint_address)

    if not code_section:
        raise ValueError(
            "No valid code section found in file " + filepath)

    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    arch = _determine_architecture(pe)
    md = Cs(CS_ARCH_X86, arch)

    # Skip: int3 debug instructions (why?)
    instructions = [decode(instr)
                    for instr in md.disasm(code_dump, code_addr) if instr.mnemonic != "int3"]

    return (arch, instructions)


def _determine_architecture(pe):
    return CS_MODE_32 if pe.FILE_HEADER.Machine == 332 else CS_MODE_64
