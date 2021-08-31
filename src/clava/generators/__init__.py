from clava.models import Signature

from clava.generators.logregtf import LogRegTF


def generate(generator, sample) -> Signature:
    """
    Generate a signature from a sample.

    Args:
        generator: Signature generation strategy.
        sample: Sample to create signature for.
    """
    if not hasattr(generator, 'generate'):
        raise TypeError("Generator must have a generate method!")

    return generator.generate(sample)
