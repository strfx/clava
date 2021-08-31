"""
Generate signatures using a Logistic Regression trained on Term Frequencies.
"""
from pathlib import Path
from typing import List
from clava.models import Sample, Instruction

from nltk import ngrams
from joblib import load

from clava.signatures import Signature, Sample


# TODO: Parent object: Classifier; SignatureGenerator; GenerationStrategy;:q

class LogRegTF(object):
    """
    Create signatures by applying Term Frequency and Logistic Regression.

    Args:
        logit: Trained logistic regression model.
        vectorizer: Fitted TF vectorizer
        n: Number of sequences to use for a signature.

    """

    def __init__(self, logit, vectorizer, n):
        self.logit = load(logit)
        self.vectorizer = load(vectorizer)
        self.n = n

    def generate(self, sample: Sample, topk: int) -> List[Instruction]:
        """
        """
        ranked = self._rank_instructions(sample.code)
        return ranked[:topk]

    def _rank_instructions(self, disassembly: List[Instruction]):
        """
        Rank instructions by their "maliciousness".
        """
        N = 6  # size of ngrams

        code_ngrams = list(ngrams(disassembly, N))

        # Extract opcodes from disassembly to classify sequence
        opcode_sequences = [
            " ".join(instr.mnemonic for instr in gram)
            for gram in code_ngrams
        ]

        # Transform opcode sequence into TF vector
        transformed = self.vectorizer.transform(opcode_sequences)

        # Classify transformed vectors
        classified = self.logit.predict_proba(transformed)

        # Combine classification results with ngrams
        sequences = zip(classified, code_ngrams)

        # Sort sequences by their "maliciousness"
        return sorted(sequences, key=lambda e: e[0][0], reverse=True)
