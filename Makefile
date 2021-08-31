# Makefile for clava
#
# Collects various commands for working with the codebase. Should make your
# life easier by not having to remember the commands.
#
# Important: Run this Makefile always in a virtualenv!
#
init:
	pip install --editable .
	pip install --upgrade -r requirements.txt

update-deps:
	pip install --upgrade pip-tools pip setuptools
	pip-compile

update: update-deps init

tests:
	pytest tests/ -v -x

lint:
	mypy src/ --ignore-missing-imports

clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -delete
	rm -rf .mypy_cache

.PHONY: tests clean init update-deps update
