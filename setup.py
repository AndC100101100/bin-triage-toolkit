"""
Thin shim — project metadata now lives in pyproject.toml (PEP 621).
Kept so `pip install -e .` works on older tooling.
"""

from setuptools import setup

setup()
