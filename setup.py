#!/usr/bin/env python
# encoding: utf-8

import sys
import os
from setuptools import setup, find_packages
from tiny_http_server import __version__

if sys.version_info < (3, 7):
    sys.exit("ERROR: tiny-http-server requires Python 3.7+")

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as f:
    readme = f.read()


setup(
    name="tiny-http-server",
    version=__version__,
    author="Johann Petrak",
    author_email="johann.petrak@gmail.com",
    url="https://github.com/johann-petrak/python-tiny-http-server",
    keywords=["tools", "http", "https", "server"],
    description="Simple ad-hoc static web page server with basic auth and https support",
    long_description=readme,
    long_description_content_type="text/markdown",
    python_requires=">=3.7",
    platforms="any",
    license="MIT License",
    packages=find_packages(),
    entry_points={"console_scripts": ["tiny-http-server=tiny_http_server.server:main"]},
    classifiers=[
        # "Development Status :: 6 - Mature",
        # "Development Status :: 5 - Production/Stable",
        "Development Status :: 4 - Beta",
        # "Development Status :: 3 - Alpha",
        # "Development Status :: 2 - Pre-Alpha",
        # "Development Status :: 1 - Planning",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Intended Audience :: Developers",
    ],
)
