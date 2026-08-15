# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from setuptools import setup, find_packages

setup(
    name="LightPacket",
    version="0.0.1",
    packages=find_packages(),  
    package_data={
        'LightPacket': ['lib/libpcap_writer.so','lib/libpcap_reader.so'],
    },
    include_package_data=True,
    install_requires=[],
    author="Adam Boulaaz",
    keywords="packet manipulation, networking, security, scanning, framework",
    python_requires=">=3.8",
    license="MPL-2.0",
    classifiers=[
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL-2.0)",
    ],
    long_description="README.md",
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
