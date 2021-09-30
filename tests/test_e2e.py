"""
Test regimen:
We don't test:
- pefile PE parsing
- capstone disassembling
- YaraGenerator's correctnes (i.e., generates correct format)
"""

from typing import List, Tuple

import capstone
import pytest

from clava.disassembling import DisassembledInstruction
from clava.inference import DummyClassifier
from clava.output import generate_yara_rule


@pytest.fixture
def disassembly() -> Tuple[int, List[DisassembledInstruction]]:
    """
    Example disassembly taken from https://alexaltea.github.io/capstone.js/

    Addr.	    Bytes	    Instr.	Operands
    00010000	55          push	rbp
    00010001	31 D2   	xor	edx, edx
    00010003	89 E5	    mov	ebp, esp
    00010005	8B 45 08	mov	eax, dword ptr [rbp + 8]
    """
    mode = capstone.CS_MODE_64

    program = [
        ("PUSH", "RBP", b"\x55"),
        ("XOR", "EDX, EDX", b"\x31\xD2"),
        ("MOV", "EBP, ESP", b"\x89\xE5"),
        ("MOV", "EAX, DWORD PTR [RBP + 8]", b"\x8B\x45\x08")
    ]

    return (mode, program)


def test_generate_yara_signature(disassembly):
    model = DummyClassifier()
    mode, instructions = disassembly

    # take all 4 sequences, so we can assume they are always present
    sequences = model.rank(instructions, topk=4)

    signature = generate_yara_rule("clava_test_rule", sequences, mode)

    assert signature.startswith("rule clava_test_rule")

    # Assert wildcarding arguments
    assert "8B 45 ??" in signature
