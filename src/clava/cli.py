"""clava v1.0

Generate Code-Based Yara Rules.

Usage:
    clava_cli.py signature <file> [--n=<sequences>] [--strategy=<strategy>]
    clava_cli.py yara <file> [--n=<sequences>] [--strategy=<strategy>] [--output=<output file>]
    clava_cli.py dump <file>

Options:
    -h --help               Show this message.
    --version               Show version of clava.
    --n=<sequences>         Size of the sequences [default: 3].
    --strategy=<strategy>   Signature generator to use [default: logreg-tf].

"""
import sys
import warnings
from operator import attrgetter
from pathlib import Path
from typing import Dict, Literal

from docopt import docopt
from pefile import PEFormatError

from clava.crafting import to_yara
from clava.generators.logregtf import LogRegTF
from clava.io import disassemble, disassembleX
from clava.models import Signature

# Suppress sklearn warnings for now (version mismatch)
warnings.filterwarnings("ignore", category=UserWarning)


def abort(msg):
    print("ERROR:", msg, file=sys.stderr)
    sys.exit(1)


def input_file(filepath: str):
    path_to_file = Path(filepath)

    if not path_to_file.exists():
        abort("No such file or directory: " + path_to_file.name)

    return path_to_file


def generate_signature(
    arguments: Dict,
    signature_format: Literal['plain', 'yara']
):
    """
    Generate a signature for the provided binary.

    Currently, clava supports two signature formats:
      * plain: Returns the internal representation of a signature, used for
               debugging.

      * yara: Returns a yara rule, which can be directly used with
              the official yara binaries (or yarac for compilation)

    Unless you are working on new models, you'll want 'yara'.

    NOTE: At the moment, we only support signatures for Portable Executables
          (PE) files. Other exectuable formats such as ELF are not supported,
          but could be added easily.

    """
    # Binary to create signature for
    input_sample = input_file(arguments['<file>'])
    # Store the resulting rule in this file (or write to stdout)
    output_file = arguments.get('--output', None)
    # How many sequences (i.e., opcode n-grams) to include in the signature
    num_sequences_in_signatures = int(arguments.get('--n', 3))

    print(f"[*] Creating signature for {input_sample.name} "
          f"(with: n={num_sequences_in_signatures})")

    try:
        sample = disassembleX(Path(input_sample))
    except PEFormatError:
        abort(f"Sample '{input_sample.name}' is not a valid PE file.")
    except ValueError:
        abort(
            f"Unable to locate code section in sample: '{input_sample.name}',"
            "might be obfuscated, packed or encrypted."
        )

    # TODO: Actually load the correct strategy from CLI arguments.
    strategy = LogRegTF(
        'wipro/models/simple-tf-logreg/logregtf.joblib',
        'wipro/models/simple-tf-logreg/tfvectorizer.joblib',
        num_sequences_in_signatures
    )

    # `generate` ranks all opcode sequences by their maliciousness and returns
    # the top-k sequences, which we'll put 1:1 in a signature.
    sequences = strategy.generate(sample, num_sequences_in_signatures)

    if signature_format == "yara":
        # Format signature as a Yara rule
        yara_rule_str = to_yara(
            "clava_" + sample.filename,
            sequences,
            dict(architecture=sample.architecture)
        )

        # Always display the generated rule
        print(yara_rule_str)

        if output_file:
            with open(output_file, 'w') as fd:
                fd.write(yara_rule_str)

            print("[*] Yara Rule written to " + output_file)
    elif signature_format == "plain":
        # plain format is used during development and probably makes not much
        # sense to anyone else. This format just outputs the sequence of
        # mnemonics in the selected sequences, e.g.,
        #
        # Signature(
        #   sequences=[
        #       'shl xor xor xor movabs and',
        #       'shl lea movsxd shl lea test',
        #       'lea shl xor xor xor movabs'
        # ])
        topk_mnemonics = []
        for seq in sequences:
            topk_mnemonics.append(" ".join(e.mnemonic for e in seq[1]))

        signature = Signature(topk_mnemonics)
        print("[!] Got: ", signature)


def dump(arguments):
    """
    Dump the instructions of the passed binary.
    """
    binary = input_file(arguments['<file>'])

    try:
        _, instructions = disassemble(
            binary,
            decode=attrgetter('mnemonic')
        )
    except PEFormatError:
        abort(binary.name + " does not appear to be a valid PE file.")

    print(f"{binary}: ({','.join(instructions)})")


def main():
    arguments = docopt(__doc__, version="clava v1.0")

    if arguments['signature']:
        generate_signature(arguments, "plain")

    if arguments['yara']:
        generate_signature(arguments, "yara")

    elif arguments['dump']:
        dump(arguments)


if __name__ == "__main__":
    main()
