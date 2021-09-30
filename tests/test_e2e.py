"""
Simple tests to check the "end-to-end" functionality.

We intentionally left out testing some aspects, since these aspects are merely
wrappers around frameworks, which we do not test. For example:
  
  * pefile's PE parsing logic
  * capstone's disassembling / decoding
  * mkYara's rule generation logic (i.e., the format is correct)

More elaborate tests can be added, but for now, this is fine.

TODO: Add this simple but effective e2e test:

    1. Take a random malware or goodware sample
    2. Generate a Yara rule using clava
    3. Apply the generated rule (using the official yara binaries) to the sample
    4. Verify that the signature matches the sample it was created from

"""
from clava.inference import DummyClassifier
from clava.output import generate_yara_rule


def test_generate_yara_signature_with_dummy_classifire(disassembly):
    model = DummyClassifier()
    mode, instructions = disassembly

    ranked_instructions = model.rank(instructions, topk=4)

    signature = generate_yara_rule(
        "clava_test_rule", ranked_instructions, mode)

    assert signature.startswith("rule clava_test_rule")

    # Operands must be replaced with wildcards (?? in Yara)
    assert "8B 45 ??" in signature, "does not wildcard operands!"
