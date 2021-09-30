import setuptools

with open("README.md", "r", encoding="utf-8") as fd:
    long_description = fd.read()

setuptools.setup(
    name="clava",
    version="1.0.0",
    author="Claudio Pilotti",
    author_email="claudio.pilotti@bluewin.ch",
    description="Generate Code-Based Yara Rules using Machine Learning.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/strfx/clava",
    project_urls={
        "Bug Tracker": "https://github.com/strfx/clava/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": ["clava=clava.cli:main"],
    },
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.8.0",
    install_requires=[
        'capstone>=4.0.2',
        'pefile>=2019.4.18',
        'mkYARA>=1.0.0',
        "joblib>=0.17.0",
        "nltk>=3.5",
        "docopt>=0.6.2",
        "scikit-learn>=0.23.2"
    ],
    extras_require={
        'dev': [
            'pytest',
            'mypy',
            'pandas',   # TODO: Remove pandas dep
            'hypothesis'
        ]
    }
)
