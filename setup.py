from setuptools import setup, find_packages

setup(
    name="repohound",
    version="0.2.0",
    description="Search source code repos by keyword — auto-scans for malware, viruses, token stealers. Deep scan mode included.",
    author="RenzyArmstrong",
    url="https://github.com/RenzyArmstrong/repohound",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "repohound=repohound.cli:main",
        ],
    },
    install_requires=[],
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Software Development :: Code Search",
    ],
)
