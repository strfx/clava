"""
Create malware signatures using the trained ML models.

To identify sequences of instructions (here: n-grams) which are likely to
appear in malware, we let a classifier evaluate the class probability of a
given sequence and use the probability to rank a list of sequences.

We then take the top-k sequences (i.e., the sequences of the disassembled
program that are most likely to appear in malware rather than goodware) and
generate the signature.

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
#
# TODO: This could be further simplified.
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
            instructions: A list of instructions, i.e., usually a disassembled
                program, but rank() accepts any sequence of instructions.

            topk: Only keep the k most "malicious" sequences.

        Returns:
            A ranked list of RankedInstructions, sorted by their maliciousness,
            i.e., the probability of how likely this instruction appears in
            malware. Sorted in descending order, meaning most malicious first.

            Classifier must always return RankedInstruction with the *complete*
            instruction (DisassembledInstruction). Must kept in mind since
            a classifier might only use a subset of the features.

        """
        pass


class LogRegClassifier(Classifier):
    """
    LogRegClassifier uses the logistic regression model.

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
        # Build ngrams:
        # Generate n-grams of the disassembly to generate more candidates,
        # then classify the n-grams.
        disassembly_ngrams = list(nltk.ngrams(instructions, self.ngram_size))

        # The model uses ngrams of mnemonics, e.g.
        #   [('add', 'push', 'xor'), ('push', 'xor', 'and'), ...]
        # But to generate the rule, we require the full raw bytes.
        # Therefore, we create n-grams on the full binary, and then
        # extract the mnemonics from them. Then we can re-combine them later.
        # We use a generator expression for that
        # documents = ["add push xor", "push xor and"]
        documents = (
            " ".join(instr[0] for instr in ngram)
            for ngram in disassembly_ngrams
        )

        # Transform opcode sequence into TF vector
        transformed = self.vectorizer.transform(documents)

        # Classify transformed vectors
        # predict_proba returns the class probabilites for each sample
        # a list of lists, e.g.
        # [[0.4, 0.6], [0.7, 0.3], ...]
        # Therefore, we need to re-join them with the disassembly ngrams.
        probabilities = self.classifier.predict_proba(transformed)

        # Combine classification results with ngrams
        # sequences = [(scores, ngrams)]
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
        sequences = list(zip(probabilities, disassembly_ngrams))

        return sort_by_maliciousness(sequences)[:topk]


class BaselineClassifier(Classifier):
    """
    Implements the static baseline approach.

    The baseline approach is documented in the paper. TL;DR: It is simply
    data-mining a large number of legitimate software samples to remove all
    possible instruction sequences that appear in the goodware corpus. This
    approach guarantees that within that corpus (and only within that) there are
    no false positive matches (i.e., the instruction sequence matches a goodware
    sample).  However, this approach is computationally very, very expensive.

    """

    def __init__(self, corpus_benign):
        self.corpus_benign = corpus_benign

    def rank(self, instruction_sequences, topk):
        # p
        # Split sample into sequences of length n (non overlapping)
        # unique since we do not care about duplicate sequences
        sequences = unique_chunks(instruction_sequences, n=6)

        mnemonics_only = (
            " ".join(instr[0] for instr in ngram)
            for ngram in sequences
        )

        # Track sequences that also appear in goodware.
        appear_in_goodware = set()

        # Manually check each sequence against each goodware sample
        # to filter out sequences that also appear in goodware.
        for goodware in self.corpus_benign.samples:
            for sequence in mnemonics_only:
                if " ".join(sequence) in goodware.code:
                    appear_in_goodware.add(sequence)

        candidates = mnemonics_only - appear_in_goodware
        if len(candidates) < 1:
            return None

        ranked = []

        # Randomly choose candidates for signature
        candidates = random.choices(tuple(candidates), k=topk)
        for i in range(topk):
            ranked.append(
                (1, 0),
                candidates[i]
            )

        return ranked

        # Form signature string from individual sets
        # candidates = [" ".join(candidate) for candidate in candidates]

        # p(malicious) = 1, p(benign) = 0
        # Comply with the return format

        # p_malicious, p_legit = 1, 0

        # x = [
        #     (p_malicious, p_legit), (None, None, )
        # ]

        # return candidates


class DummyClassifier(Classifier):
    """
    Dummy to demonstrate how to implement a (simple) classifier.

    Mostly used for testing purposes, but can also act as a baseline.
    """

    def rank(self, instructions, topk) -> List[RankedInstructions]:
        """
        Randomly rank instruction sequences.
        """
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
    """
    Sort instruction sequences by their "maliciousness"
    """
    return sorted(ranked_not_sorted, key=lambda seq: seq[0][0], reverse=True)
