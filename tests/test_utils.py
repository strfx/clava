from hypothesis import given, strategies as st

from clava.utils import unique_chunks


@given(
    data=st.lists(st.integers()),
    chunk_size=st.integers()
)
def test_unique_chunks_properties(data, chunk_size):
    """
    unique_chunks must fulfill two properties:
    - Each chunk must be <= given chunk size
    - Each chunk must be unique
    """
    chunks = unique_chunks(data, chunk_size)

    assert set(chunks) == chunks
    assert all(len(chunk) <= chunk_size for chunk in chunks)
