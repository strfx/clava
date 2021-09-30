"""
Convert generated signature into an actually usable signature (i.e., Yara).
"""
from capstone import CS_ARCH_X86
from mkyara import YaraGenerator

from clava import __version__


def generate_yara_rule(name: str, sequences, mode: int) -> str:
    """ Returns signature formatted as a Yara rule. """

    # Metadata strings must always be wrapped in quotes.
    metadata = {
        "generated_by": f'"Clava v{__version__} & mkYARA (by Jelle Vergeer)"'
    }

    generator = YaraGenerator(
        "loose",        # Wildcard all operands (i.e., only keep operations)
        CS_ARCH_X86,    # We always assume the binary is made for x86 platform
        mode,           # 32-/64-bit (affects opcode decoding)
        rule_name=name
    )

    for _, ngrams in sequences:
        raw_bytes_combined = [instr_bytes for *_, instr_bytes in ngrams]
        generator.add_chunk(b"".join(raw_bytes_combined))

    rule = generator.generate_rule()

    # Add AND condition over chunks
    rule.condition = " and ".join(s.key for s in rule.strings)

    # Add metadata to the rule (will be added to the yara's `meta:` block)
    rule.metas.update(metadata)

    return rule.get_rule_string()
