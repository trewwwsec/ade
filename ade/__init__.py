#!/usr/bin/env python3
"""
ADE - Automated Active Directory Enumeration

A Python script that automates Active Directory (AD) enumeration in lab environments,
helping users on Hack The Box, Hack Smarter, TryHackMe, Proving Grounds, or exams
like OSCP and CPTS streamline initial AD recon.

Author: Blue Pho3nix
"""

from .config import __version__
from .cli import main

__all__ = ["main", "__version__"]
