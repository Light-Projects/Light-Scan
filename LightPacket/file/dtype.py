# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

def detect_file_type(filename):
    try:
        with open(filename, 'rb') as f:
            magic = f.read(4)
            if magic == b'LBN\x00':
                return 'lightbin'
            elif magic[:4] == b'\xd4\xc3\xb2\xa1' or magic[:4] == b'\xa1\xb2\xc3\xd4' or magic[:4] == b'M<\xb2\xa1':
                return 'pcap'
            elif magic[:4] == b'\x0a\x0d\x0d\x0a':
                return 'pcapng'
            else:
                return 'unknown'
    except:
        return 'unknown'