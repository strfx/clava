"""
Clava Signatures
"""
from collections import namedtuple
from enum import Enum, IntEnum
from dataclasses import dataclass
from typing import List, Set


# An assember instruction

# Contains the mnemonic (e.g., PUSH, POP, XOR, AND ...) and the
# raw bytes representation (like b"0d1d) (opcode + operand)
Instruction = namedtuple('Instruction', 'mnemonic, bytes')

# A program's disassembly is the set of all its instructions.
Disassembly = List[Instruction]


class Label(Enum):
    """
    Enum to represent a sample's label.
    """
    LEGITIMATE = 0
    MALICIOUS = 1


def _sequence_in_code(sequence: str, code: str) -> bool:
    """
    Check if signature sequence appears in code.

    Args:
        sequence: Component of a signature to apply.
        code: Disassembled code of the sample.

    Returns:
        True if sequence appears in code, else False.

    """
    if not (isinstance(sequence, str) and isinstance(code, str)):
        raise TypeError(
            f"Input data must be string, got {type(sequence)} and {type(code)}")

    return sequence in code


@dataclass
class Signature:
    """
    Signature domain model.

    A signature consists of a number of string sequences.
    """

    sequences: List[str]

    def match(self, sample) -> bool:
        """
        Apply signature on a document.

        Signature matching is performed by applying all sequences using
        a logical AND. That means, the signature "matches" if and only if
        all sequences appear in the sample.

        Args:
            sample: Sample to apply signature on.

        Returns:
            True if the signature matches the document, else False.

        """
        return all(_sequence_in_code(sequence, sample.code) for sequence in self.sequences)


@dataclass(frozen=True)
class Sample:
    """
    Sample is a disassembled good- or malware file.
    """

    filename: str
    filesize: int
    architecture: int
    code: List[Instruction]
    label: Label
