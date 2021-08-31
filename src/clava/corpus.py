"""
Manage corpora (i.e., large collections) of malicious- or goodware samples.
"""
from dataclasses import dataclass
from typing import List, Set, Tuple

from clava.models import Sample, Signature, Label


@dataclass
class Corpus:

    label: Label
    samples: List[Sample]

    def match(self, signature: Signature) -> Set[Sample]:
        """
        Apply signature to all samples in corpus.

        Args:
            signature: Signature to apply.

        Returns:
            A set of documents that match the signature.

        """
        return {sample for sample in self.samples if signature.match(sample)}

    @classmethod
    def from_dataframe(cls, df) -> Tuple['Corpus', 'Corpus']:
        """
        Create corpus from a pandas dataframe.

        Args:
            df: A pandas dataframe.

        Returns:
            Two corpora, for malware and goodware respectively.

        """

        goodware, malware = [], []
        architecture = 0    # Unknown in this dataset
        for _, row in df.iterrows():

            label = Label(int(row.label))

            sample = Sample(
                row.filename,
                row.size,
                architecture,
                row.sequence,   # TODO
                label
            )

            if label == Label.MALICIOUS:
                malware.append(sample)
            else:
                goodware.append(sample)

        return (
            Corpus(Label.LEGITIMATE, goodware),
            Corpus(Label.MALICIOUS, malware)
        )
