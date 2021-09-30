"""
Disassemble binaries i.e., legitimate or malicious executables.

Clava uses the Capstone Engine to disassemble binaries. Keep in mind that
disassembling is a hard and error-prone process and there are many pitfalls.
We've kept the disassembling straightforward and ignored many edge cases.
It worked well enough in our experiments, hence we did not pursue any
improvements here.

Also, clava only supports programs written for x86 architecture and in the
Portable Executable (PE) format. Other exectuable formats such as ELF are not
supported, but could be added easily.
"""
from pathlib import Path
from typing import List, Tuple

import capstone
import pefile


class NoCodeSectionError(Exception):
    """
    Raise NoCodeSection if we fail to decode an executable's code section.

    The most common cases where this can happen are:
      * The executable is corrupt or malformatted
      * The executable is obfuscated, packed or encrypted, i.e., the
        executables code will be unpacked / decrypted upon execution.

    Clava does not explicitely support generating signatures for executables
    that are packed, encrypted or in any other form obfuscated. 
    """
    pass


# An instruction consists of two components: an operation and operands e.g.,
# 'MOV EBP, ESP' where 'MOV' represents the operation, and 'EBP' and 'ESP' are
# the operands. We also keep the raw bytes, since we generate code-based
# signatures later which must match on the actual bytes, not the disassembled
# instructions.
#
# Example: ("MOV", "EBP, ESP", b"\x89\xE5")
DisassembledInstruction = Tuple[str, str, bytearray]


def disassemble(executable_location: Path) -> Tuple[int, List[DisassembledInstruction]]:
    """
    Disassemble an executable.

    To disassemble an executable, we locate the program's code section,
    extract the raw bytes and then decode the instructions.

    Args:
        executable_location: Location of the executable to be disassembled. This
            must be a valid Portable Executable (PE) file, other executable
            formats (like ELF) are not supported.

    Returns:
        A tuple (mode, instructions) where mode indicates whether the binary
        was compiled for 32-bit or 64-bit platforms and instructions is the
        list of disassembled instructions (order of the list corresponds to
        the program's flow).

    Raises:
        pefile.PEFormatError: If the binary is not a valid PE file.
        NoCodeSectionFoundError: Raised when the binary has no code section, or
            if the section could not be decoded (e.g., binary is obfuscated or
            encrypted). 
    """
    pe = pefile.PE(str(executable_location))

    entrypoint_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(entrypoint_address)

    if not code_section:
        raise NoCodeSectionError(
            f"No valid code section found in file: {executable_location.name}."
        )

    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress

    # We only support x86, hence we assume the sample is x86.
    arch = capstone.CS_ARCH_X86
    # The mode (32-bit / 64-bit) affects how the instructions are decoded.
    mode = capstone.CS_MODE_32 if pe.FILE_HEADER.Machine == 332 else capstone.CS_MODE_64

    decoder = capstone.Cs(arch, mode)

    # Actually disassemble the input binary
    #
    # TODO: Why do we skip the INT3 debug instruction? It could actually
    #       be an interesting instruction used by malware, e.g., for
    #       anti-debug checks.
    instructions = [
        (instr.mnemonic, instr.op_str, instr.bytes)
        for instr in decoder.disasm(code_dump, code_addr)
        if instr.mnemonic != "int3"
    ]

    return (mode, instructions)
