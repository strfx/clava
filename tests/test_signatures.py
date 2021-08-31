
import pytest

from clava.signatures import match, _match_opcode_sequences
from clava.models import Label, Sample, Signature


@pytest.mark.parametrize('sequences, code, should_match', [
    # Should match target with signature at the very beginning
    ([("incr", "xor", "add")],  "incr xor add add add pop", True),

    # Should match target at the end
    ([("add", "add", "pop")], "incr xor add add add pop", True),

    # Should match target with signature somewhere in the middle
    ([("add", "add", "add")], "incr xor add add add pop", True),

    # Should only match on continuous signatures, not just on words
    ([("incr", "xor", "pop")], "incr xor add add add pop", False),

    # Should apply multiple signatures
    (
        [("incr", "xor"), ("add", "add")],
        "incr xor add add add pop",
        True
    ),

    # Should apply multiple signatures in AND manner, not OR
    (
        [("incr", "xor"), ("add", "xor")],
        "incr xor add add add pop",
        False
    ),
])
def test_match_opcode_sequences(sequences, code, should_match):
    """
    Should correctly apply opcode signatures on a sample.
    """
    signature = Signature(sequences)
    sample = Sample("a", 1, 1, code, Label.MALICIOUS)
    assert _match_opcode_sequences(signature, sample) == should_match


def test_match_signature_on_samples():
    """
    Corpus should apply signature on all documents.
    """
    some_signature = Signature([("incr", "xor")])
    some_samples = [
        Sample('some.bytes', 1, 1, "incr xor add add add pop", Label.MALICIOUS),
        Sample('more.bytes', 1, 1, "add xor add add add pop", Label.MALICIOUS),
        Sample('other.bytes', 1, 1, "add add incr xor add pop", Label.MALICIOUS),
    ]

    should_match = [True, False, True]

    expected = list(zip(some_samples, should_match))

    assert match(some_signature, some_samples) == expected
