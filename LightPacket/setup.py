# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="lightpacket",
    version="0.0.4",
    packages=find_packages(),
    package_data={
        'LightPacket': ['lib/*.so', 'lib/*.dll', 'lib/*.dylib','data/*.txt','helper/protos/*.json'],
    },
    include_package_data=True,
    install_requires=[],
    author="Adam Boulaaz",
    keywords="packet manipulation, networking, security, scanning, framework",
    python_requires=">=3.8",
    license="MPL-2.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/adamboulaaz92-jpg/LightPacket",
    project_urls={
            "Bug Tracker": "https://github.com/adamboulaaz92-jpg/LightPacket/issues",
            "Source Code": "https://github.com/adamboulaaz92-jpg/LightPacket",
        },
    author_email="adamboulaaz92@gmail.com",
    description="Light-Scan Framework Custom Packet Manipulation Library",
    zip_safe=False,
)