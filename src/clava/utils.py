"""
Project-wide helpers and utilites.
"""


def unique_chunks(lst, n):
    """ Returns unique chunks of length n from lst.  """
    if n < 1:
        return set()

    return {tuple(lst[i:i + n]) for i in range(0, len(lst), n)}
