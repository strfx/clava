"""clava v1.0: Generate code-based Yara rules.

Usage:
    clava yara <file> [--topk=<sequences>] [--output=<output file>]

Options:
    -h --help               Show this message.
    --version               Show version of clava.
    --topk=<sequences>      Number of instruction sequences to use [default: 3].
    --output=<output file>  Store the generated rule in this file.

"""
import sys
from pathlib import Path

from docopt import docopt
from pefile import PEFormatError

from clava.disassembling import disassemble
from clava.inference import LogRegClassifier
from clava.output import generate_yara_rule

# TODO: Make paths configurable via CLI.
CLASSIFIER_PATH = Path('wipro/models/simple-tf-logreg/logregtf.joblib')
VECTORIZER_PATH = Path('wipro/models/simple-tf-logreg/tfvectorizer.joblib')


def abort(msg):
    print("ERROR:", msg, file=sys.stderr)
    sys.exit(1)


def generate_signature(arguments):
    """
    Generate a Yara rule for given (malware) sample.
    """
    # Binary to create signature for
    sample = Path(arguments['<file>'])

    # Store the generated rule in this file if provided; Either way, the rule
    # will always be written to stdout too.
    output_file = arguments.get('--output', None)

    # How many sequences (i.e., mnemonic n-grams) to include in the signature
    num_sequences_in_signatures = int(arguments.get('--topk', 3))

    try:
        mode, disassembly = disassemble(sample)
    except PEFormatError:
        abort(f"Sample '{sample.name}' is not a valid PE file.")
    except ValueError:
        abort(
            f"Unable to locate code section in sample: '{sample.name}',"
            "might be obfuscated, packed or encrypted."
        )

    model = LogRegClassifier(CLASSIFIER_PATH, VECTORIZER_PATH, ngram_size=6)

    sequences = model.rank(disassembly, topk=num_sequences_in_signatures)

    yara_rule_str = generate_yara_rule("clava_" + sample.name, sequences, mode)

    print(yara_rule_str)

    if output_file:
        Path(output_file).write_text(yara_rule_str)


def main():
    arguments = docopt(__doc__, version="clava v1.0")
    if arguments['yara']:
        generate_signature(arguments)
