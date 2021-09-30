"""
Contains helpers to train the model.

NOTE: Most of the training code and documentation is burried in Jupyter
notebooks. The notebooks will be released at some point in the future and
we are migrating more and more of the training code & docs into this package.

This module contains:
- Evaluation logic -- how would a candidate signature perform in the wild?
    -- used to compare approaches

Evaluation
----------
Not to be confused with the evaluation function that evaluates the model's
performance in terms of classification accuracy. This evaluation is used to
compare the performance of individual approaches (e.g., a trained model vs the
baseline).

Corpus
------
Disassembling executables requires some time. Processing all executables in the
corpus during training / modeling would slow this process down. Thus, we
disassemble all executables once and store the required features in a text file,
where it can be loaded from quickly.

 """
from collections import namedtuple
from dataclasses import dataclass
from typing import Callable, List, Tuple


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
