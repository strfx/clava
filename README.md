<h1 align="center">
  clava 🔍
  <br>
</h1>

<h4 align="center">Generate Code-Based <a href="https://virustotal.github.io/yara/" target="_blank">Yara</a> Rules using Machine Learning.</h4>
<p align="center">  
  <a href="https://github.com/strfx/clava/actions" target="_blank">
    <img src="https://img.shields.io/github/workflow/status/strfx/clava/build" />
  </a>
  <a href="https://github.com/strfx/clava/blob/main/LICENSE" target="_blank">
     <img src="https://img.shields.io/badge/License-MIT-blue.svg" />
  </a>
  <a href="http://mypy-lang.org/" target="_blank">
     <img src="http://www.mypy-lang.org/static/mypy_badge.svg" />
  </a>
</p>

<p align="center">
  <img src="https://github.com/strfx/clava/blob/main/docs/cli.png?raw=true" alt="clava CLI"/>
</p>

# Table of Contents

  * [About](#about)
  * [Getting Started](#getting-started)
  * [Development](#development)
  * [Contribute](#contribute)
  * [Resources](#resources)
  * [Credits](#credits)

# About

I wrote clava for an industry project during my studies at Hochschule Luzern. This project researches how to automatically generate code-based [Yara](https://virustotal.github.io/yara/) rules for a given malware sample using machine learning. We've kept the machine learning part intentionally rudimentary to demonstrate how much can be achieved with basic methods. The research is documented in a paper (German only). Contact me if you are interested in the paper.

TL;DR: clava creates n-grams of mnemonics (e.g., `XOR` or `PUSH`) of good- and malware and trains a logistic regression classifier on the n-gram's term frequency weights. We drop the operands as they are subject to change and only keep the instruction's operation part to improve the robustness of the rules. Dropping the operands requires to wildcard the Yara rules. We are using [mkYARA](https://github.com/fox-it/mkyara) (kudos!) for that task. 

We've kept the methodology overly simplistic to demonstrate what can be achieved and also due to the project's time constraints. Using n-grams of mnemonics (where *n* is small) is simple but lacks semantic meaning - a malware analyst would have a hard time figuring out the context of the output sequence. Semantic meaning can be achieved by increasing the n-grams size (see also [KiloGrams: Very Large N-Grams for Malware Classification](https://www.edwardraff.com/publications/kilograms.pdf)) or by using semantically meaningful features in the first place, such as function bodies of the disassembled binaries. Further, one could explore more elaborate models such as sequence models like RNNs.

The trained models are not public. However, you can train a model on your own dataset. Instructions will follow.


# Getting Started

To install `clava`, clone this repository and run (preferably in a virtualenv):

```sh
$ pip install -r requirements.txt
$ python setup.py install
```

clava offers a simple CLI to interact. To list all available options, run:

```sh
$ clava -h
```

To generate a yara rule based on a sample:

```sh
$ clava yara <path/to/sample>
```

**Important:** Rules created with clava should **not** directly be used in production, but can assist during rule development. This project is heavily inspired by [yarGen](https://github.com/Neo23x0/yarGen), therefore see also Floriah Roth's [blog post](https://cyb3rops.medium.com/how-to-post-process-yara-rules-generated-by-yargen-121d29322282) *"How to post-process YARA rules generated by yarGen"*.

# Development

During development, install `clava` in editable mode:

```sh
$ pip install -e .[dev]
```

## Running the tests

clava uses [pytest](https://docs.pytest.org/en/6.2.x/). To run the test suite with a set of predefined settings, run:

```sh
$ make tests
```

Alternatively, you can run pytest against the `tests/` directory with your own settings.

# Contribute

Contributions are welcome! If you plan major changes, please create an issue first to discuss the changes.

# Resources

Good datasets are essential, however there are not many public datasets of good- and malware executables. You can assemble your own dataset using projects like:

* [VirusShare](https://virusshare.com/) offers access to large amounts of malware (registration required).
* [MalwareBazaar](https://bazaar.abuse.ch/) offers daily collections of malware: https://mb-api.abuse.ch/downloads/
* [APTMalware Github Repo](https://github.com/cyber-research/APTMalware)
* [Sysinternals Tools](TODO) are a great set to test your rules against, since Sysinternals tools often cause false positive hits.

Public goodware datasets are rare - PRs are welcome :smile:

Tools:
* [Capstone.js](https://alexaltea.github.io/capstone.js/) for interactive disassembling, useful during development.

# Credits

clava was heavily inspired by these projects:

* [yarGen](https://github.com/Neo23x0/yarGen)
* [yara-signator](https://github.com/fxb-cocacoding/yara-signator)
* [binsequencer](https://github.com/karttoon/binsequencer/)
* [yabin](https://github.com/AlienVault-OTX/yabin)

I would also like to thank these projects:
* [pefile](https://pypi.org/project/pefile/)
* [Capstone Disassembler](https://www.capstone-engine.org/)