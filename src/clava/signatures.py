"""
Signature matching logic.

Clava itself does not perform any yara rule matching. However, to measure the
quality of a generated rule during training, we need a simple heuristic how
the rule would perform.
"""
from collections import namedtuple
from typing import Callable, Tuple, List

from clava.models import Sample, Signature


def _match_opcode_sequences(signature: Signature, sample: Sample) -> bool:
    """
    Apply signature on a sample by AND'in the opcode sequences.

    Nothing fancy here -- just converting the sequences into a string
    and perform a substring match. Could be improved though.
    """
    return all(" ".join(sequence) in sample.code for sequence in signature.sequences)


def match(
    signature: Signature,
    samples: List[Sample],
    matcher: Callable[[Signature, Sample], bool] = _match_opcode_sequences
) -> List[Tuple[Sample, bool]]:
    """
    Apply signature on a list of samples.
    """
    return [(sample, matcher(signature, sample)) for sample in samples]
