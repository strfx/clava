"""
Create malware signatures using the trained ML models.

To identify sequences of instructions (here: n-grams) which are likely to
appear in malware, we let a classifier evaluate the class probability of a
given sequence and use the probability to rank a list of sequences.

We then take the top-k sequences (i.e., the sequences of the disassembled
program that are most likely to appear in malware rather than goodware) and
generate the signature.

TODO: Update this documentation as it does not apply to all classifiers anymore.
"""
import random
from pathlib import Path
from typing import List, Protocol, Tuple

import joblib
import nltk

from clava.disassembling import DisassembledInstruction
from clava.utils import unique_chunks

# RankedInstructions holds the instruction sequence along with the
# class probabilities for that sequence being more likely found in
# malware or legitimate software.
RankedInstructions = Tuple[
    # First tuple holds the class probabilities for the instruction sequence,
    # where first item is p(malicious) and second is p(legitimate),
    # i.e., 1 - p(malicious).
    Tuple[float, float],
    # Holds the (complete) ranked instruction sequence. 'Complete' because a
    # classifier might use only subset of features of DisassembledInstruction
    # to classify the sequence. However, it must always return the complete
    # instruction sequence.
    List[DisassembledInstruction]
]


class Classifier(Protocol):

    def rank(self, instructions: List[DisassembledInstruction], topk: int) -> List[RankedInstructions]:
        """
        Rank a list of instruction sequences by their maliciousness.

        Args:
            instructions: 
                A list of instructions, usually a disassembled program, but
                rank() accepts any sequence of instructions.

            topk: Only keep the k most "malicious" sequences.

        Returns:
            A list of RankedInstructions sorted by their maliciousness, i.e.,
            the probability of how likely this instruction sequence appears in
            malware. Sorted in descending order, meaning most malicious first.

            Classifier must always return RankedInstructions with the *complete*
            instruction (DisassembledInstruction). Must kept in mind since a
            classifier might only use a subset of the features.
        """
        pass


class LogRegClassifier(Classifier):
    """
    Ranks instruction sequences with the fitted logistic regression model.

    This classifier implements the main work of clava as of now, the full
    procedure is described in the paper. TL:DR; We fitted a logistic regression
    on the Term Frequency weights of mnemonics based on their appearances in
    malicious and legitimate software.
    """

    def __init__(self, classifier_path: Path, vectorizer_path: Path, ngram_size=6):
        self.classifier = joblib.load(classifier_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.ngram_size = ngram_size

    def rank(self, instructions: List[DisassembledInstruction], topk: int) -> List[RankedInstructions]:
        # Using n-grams, we can multiply the number of potential signature
        # components.
        instruction_ngrams = list(nltk.ngrams(instructions, self.ngram_size))

        # The model was only trained on a programs mnemonics like 'push', 'xor',
        # etc. Therefore, we extract the mnemonics in a second list, classify
        # them and combine them with the complete instructions later.
        #
        # Example: list(mnemonic_ngrams) -> ["add push xor", "push xor and"]
        mnemonic_ngrams = (
            " ".join(instr[0] for instr in ngram)
            for ngram in instruction_ngrams
        )

        # Transform the mnemonic sequences into term-frequency vectors.
        transformed = self.vectorizer.transform(mnemonic_ngrams)

        # Classify transformed vectors using fitted model, predict_proba
        # returns a list of tuples, each representing the class probabilites
        # of each sample, e.g., [[0.4, 0.6], [0.7, 0.3], ...]
        # Therefore, we need to re-join them with the disassembly ngrams.
        probabilities = self.classifier.predict_proba(transformed)

        # Combine the class probabilities with the original n-grams.
        # Example: list(sequences) ->
        # [
        #   (
        #       (array([0.49666687, 0.50333313]),
        #
        #          ('call', '0x404bfc', bytearray(b'\xe8\xd8\xfc\xff\xff')),
        #          ('mov', 'ebx, dword ptr [edi + 0x68]', bytearray(b'\x8b_h')),
        #          ('mov', 'esi, dword ptr [ebp + 8]', bytearray(b'\x8bu\x08'))
        #      )
        #   )
        # ]
        sequences = list(zip(probabilities, instruction_ngrams))

        return sort_by_maliciousness(sequences)[:topk]


class DummyClassifier(Classifier):
    """
    Ranks instruction sequences randomly.

    Used for testing and to show, how to implement a simple classifier.
    """

    def rank(self, instructions, topk) -> List[RankedInstructions]:
        ranked = []

        for i in range(topk):
            instruction_seq = random.choices(instructions, k=topk)
            class_proba = random.random()
            ranked.append((
                (class_proba, 1 - class_proba),
                instruction_seq
            ))

        return sort_by_maliciousness(ranked)[:topk]


def sort_by_maliciousness(ranked_not_sorted: List[RankedInstructions]) -> List[RankedInstructions]:
    """ Sort instruction sequences by their maliciousness. """
    return sorted(ranked_not_sorted, key=lambda seq: seq[0][0], reverse=True)
