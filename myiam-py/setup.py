# Standard Library Imports
import io
import pathlib
import re

# Third-Party Imports
from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent

README = (HERE / "README.md").read_text()


with io.open(HERE / "myiam/__init__.py", "rt", encoding="utf8") as f:
    VERSION = re.search(r'__version__ = "(.*?)"', f.read(), re.M).group(1)

setup(
    name="myiam",
    version=VERSION,
    description="MyIAM control library",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/ccortezia/myiam/",
    author="Cristiano Cortezia",
    author_email="cristiano.cortezia@gmail.com",
    license="MIT",
    install_requires=["boto3>=1.15"],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    packages=find_packages(exclude=["tests", "tests.*"]),
)
