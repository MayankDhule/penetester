#!/usr/bin/env python3
"""
Setup script for Pentestrr
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="pentestrr",
    version="1.0.0",
    author="Security Research Team",
    author_email="security@example.com",
    description="CLI web-security scanner with target profiling and tool recommendations",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MayankDhule/penetester",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "pentestrr=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
