#!/usr/bin/env python3
"""
Setup script for Wazuh DevSec Generator
Simple and clean installation system
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="wazuh-devsec-generator",
    version="2.0.0",
    author="VulneZe",
    author_email="vulnze@example.com",
    description="Générateur professionnel de configuration Wazuh pour environnement DevSec",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/VulneZe/wazuh-install",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.9",
    install_requires=[
        "jinja2>=3.0.0",
        "pydantic>=2.0.0",
        "rich>=13.0.0",
        "psutil>=5.9.0",
        "click>=8.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "wazuh-generator=wazuh_devsec_config_generator.cli:main",
            "wazuh-tui=wazuh_devsec_config_generator.tui.main_app:main",
            "wazuh-smart=wazuh_devsec_config_generator.cli:smart_main",
        ],
    },
    include_package_data=True,
    package_data={
        "wazuh_devsec_config_generator": [
            "templates/*.jinja2",
            "templates/*.jinja",
        ],
    },
    zip_safe=False,
    keywords="wazuh security devsec configuration generator",
    project_urls={
        "Bug Reports": "https://github.com/VulneZe/wazuh-install/issues",
        "Source": "https://github.com/VulneZe/wazuh-install",
        "Documentation": "https://github.com/VulneZe/wazuh-install/blob/main/README.md",
    },
)
