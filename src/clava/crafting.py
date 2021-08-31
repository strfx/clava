"""
Craft signatures that can be used with common tools like Yara.
"""
from typing import Dict, List

from capstone import CS_ARCH_X86
from mkyara import YaraGenerator

from clava import __version__
from clava.models import Instruction


def to_yara(name: str, sequences: List[Instruction], additional_config: Dict) -> str:
    """
    Returns signature formatted as a Yara rule.
    """
    arch = additional_config['architecture']

    # Overwrite rule metadata
    meta = dict(
        generated_by=f'"Clava v{__version__} & mkYARA (by Jelle Vergeer)"',
        version=f'"{__version__}"'
    )

    generator = YaraGenerator(
        "loose",        # Wildcard all operands (i.e., only keep operations)
        CS_ARCH_X86,    # We always assume the binary is made for x86
        arch,           # 32-/64-bit (affects opcode decoding)
        rule_name=name
    )

    for _, ngrams in sequences:
        raw_bytes_combined = [instr_bytes for mnemonic, instr_bytes in ngrams]
        generator.add_chunk(b"".join(raw_bytes_combined))

    rule = generator.generate_rule()

    # Add AND condition over chunks
    rule.condition = " and ".join(s.key for s in rule.strings)

    # Add metadata to the rule (will be added to the yara's `meta:` block)
    rule.metas.update(meta)

    return rule.get_rule_string()
