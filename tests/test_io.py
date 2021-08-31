from random import choice

import pandas as pd

from clava.corpus import Corpus
from clava.models import Label


TEST_DATAFILE = "wipro/stats/dataset_2k_disasm.csv"


def test_create_corpora_from_dataframe():
    dtypes = {
        "filename": "string",
        "size": "int",
        "sequence": "string",
        "label": "category"
    }

    some_dataframe = pd.read_csv(TEST_DATAFILE, dtype=dtypes)
    corpi = Corpus.from_dataframe(some_dataframe)

    assert len(corpi) == 2

    gw, mw = corpi
    assert len(gw.samples) > 0
    assert len(mw.samples) > 0

    for sample in gw.samples:
        assert sample.label == Label.LEGITIMATE

    for sample in mw.samples:
        assert sample.label == Label.MALICIOUS
