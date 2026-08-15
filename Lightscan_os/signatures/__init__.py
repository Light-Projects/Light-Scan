# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
Signature registry.

To add support for a new OS: create signatures/<yourname>.py exporting a
SIGNATURES list of OSSignature instances (see base.py), then register the
module below. Nothing else in the engine needs to change.
"""

from . import windows, linux, macos, bsd, unix, android

ALL_SIGNATURES = (
    windows.SIGNATURES
    + linux.SIGNATURES
    + macos.SIGNATURES
    + bsd.SIGNATURES
    + unix.SIGNATURES
    + android.SIGNATURES
)

# Quick lookup by display name, e.g. SIGNATURES_BY_NAME["Windows"]
SIGNATURES_BY_NAME = {sig.name: sig for sig in ALL_SIGNATURES}

# Quick lookup by family tag, e.g. SIGNATURES_BY_FAMILY["windows"]
SIGNATURES_BY_FAMILY = {sig.family: sig for sig in ALL_SIGNATURES}

__all__ = ["ALL_SIGNATURES", "SIGNATURES_BY_NAME", "SIGNATURES_BY_FAMILY"]
