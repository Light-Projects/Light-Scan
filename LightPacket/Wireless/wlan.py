"""
802.11 Wi-Fi Layer Implementation (class WiFi)
- IEEE 802.11-2020: Wireless LAN Medium Access Control (MAC)
- Frame Control | Duration | Address 1 | Address 2 | Address 3 | Sequence Control | Address 4 | QoS Control | HT Control
- Fields: version (2 bits), type (2 bits), subtype (4 bits), flags (8 bits)
"""

import struct
from ..BaseLayer import BaseLayer
from ..Logger.LightLogger import Logger, ErrorCode
from ..Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from ..Consts import OUI_MAP,MC

LLogger = Logger()

FRAME_VERSION_80211 = 0x00
FRAME_VERSION_80211A = 0x01
FRAME_VERSION_RESERVED1 = 0x02
FRAME_VERSION_RESERVED2 = 0x03

FRAME_VERSION_NAMES = {
    0x00: "802.11",
    0x01: "802.11a",
    0x02: "Reserved",
    0x03: "Reserved"
}

FRAME_TYPE_MANAGEMENT = 0x00
FRAME_TYPE_CONTROL = 0x01
FRAME_TYPE_DATA = 0x02
FRAME_TYPE_EXTENSION = 0x03

FRAME_TYPE_NAMES = {
    0x00: "Management",
    0x01: "Control",
    0x02: "Data",
    0x03: "Extension"
}

SUB_TYPE_ASSOC_REQ = 0x00
SUB_TYPE_ASSOC_RSP = 0x01
SUB_TYPE_REASSOC_REQ = 0x02
SUB_TYPE_REASSOC_RSP = 0x03
SUB_TYPE_PROBE_REQ = 0x04
SUB_TYPE_PROBE_RSP = 0x05
SUB_TYPE_TIMING_ADV = 0x06
SUB_TYPE_RESERVED_MGMT = 0x07
SUB_TYPE_BEACON = 0x08
SUB_TYPE_ATIM = 0x09
SUB_TYPE_DISASSOC = 0x0A
SUB_TYPE_AUTH = 0x0B
SUB_TYPE_DEAUTH = 0x0C
SUB_TYPE_ACTION = 0x0D
SUB_TYPE_ACTION_NO_ACK = 0x0E

MANAGEMENT_SUBTYPE_NAMES = {
    0x00: "Association Request",
    0x01: "Association Response",
    0x02: "Reassociation Request",
    0x03: "Reassociation Response",
    0x04: "Probe Request",
    0x05: "Probe Response",
    0x06: "Timing Advertisement",
    0x07: "Reserved",
    0x08: "Beacon",
    0x09: "ATIM",
    0x0A: "Disassociation",
    0x0B: "Authentication",
    0x0C: "Deauthentication",
    0x0D: "Action",
    0x0E: "Action No Ack",
    0x0F: "Reserved"
}

SUB_TYPE_PS_POLL = 0x0A
SUB_TYPE_RTS = 0x0B
SUB_TYPE_CTS = 0x0C
SUB_TYPE_ACK = 0x0D
SUB_TYPE_CF_END = 0x0E
SUB_TYPE_CF_END_ACK = 0x0F

CONTROL_SUBTYPE_NAMES = {
    0x00: "Reserved",
    0x01: "Reserved",
    0x02: "Reserved",
    0x03: "Reserved",
    0x04: "Reserved",
    0x05: "Reserved",
    0x06: "Reserved",
    0x07: "Reserved",
    0x08: "Reserved",
    0x09: "Reserved",
    0x0A: "PS-Poll",
    0x0B: "RTS",
    0x0C: "CTS",
    0x0D: "ACK",
    0x0E: "CF-End",
    0x0F: "CF-End + CF-Ack"
}

SUB_TYPE_DATA = 0x00
SUB_TYPE_DATA_CF_ACK = 0x01
SUB_TYPE_DATA_CF_POLL = 0x02
SUB_TYPE_DATA_CF_ACK_POLL = 0x03
SUB_TYPE_NULL = 0x04
SUB_TYPE_CF_ACK = 0x05
SUB_TYPE_CF_POLL = 0x06
SUB_TYPE_CF_ACK_POLL = 0x07
SUB_TYPE_QOS_DATA = 0x08
SUB_TYPE_QOS_DATA_CF_ACK = 0x09
SUB_TYPE_QOS_DATA_CF_POLL = 0x0A
SUB_TYPE_QOS_DATA_CF_ACK_POLL = 0x0B
SUB_TYPE_QOS_NULL = 0x0C
SUB_TYPE_RESERVED_DATA = 0x0D
SUB_TYPE_QOS_CF_POLL = 0x0E
SUB_TYPE_QOS_CF_ACK_POLL = 0x0F

DATA_SUBTYPE_NAMES = {
    0x00: "Data",
    0x01: "Data + CF-Ack",
    0x02: "Data + CF-Poll",
    0x03: "Data + CF-Ack + CF-Poll",
    0x04: "Null (no data)",
    0x05: "CF-Ack (no data)",
    0x06: "CF-Poll (no data)",
    0x07: "CF-Ack + CF-Poll (no data)",
    0x08: "QoS Data",
    0x09: "QoS Data + CF-Ack",
    0x0A: "QoS Data + CF-Poll",
    0x0B: "QoS Data + CF-Ack + CF-Poll",
    0x0C: "QoS Null (no data)",
    0x0D: "Reserved",
    0x0E: "QoS CF-Poll (no data)",
    0x0F: "QoS CF-Ack + CF-Poll (no data)"
}

FC_FLAG_TO_DS = 0x01
FC_FLAG_FROM_DS = 0x02
FC_FLAG_MORE_FRAG = 0x04
FC_FLAG_RETRY = 0x08
FC_FLAG_PWR_MGT = 0x10
FC_FLAG_MORE_DATA = 0x20
FC_FLAG_PROTECTED = 0x40
FC_FLAG_ORDER = 0x80

FC_FLAG_NAMES = {
    FC_FLAG_TO_DS: "To DS",
    FC_FLAG_FROM_DS: "From DS",
    FC_FLAG_MORE_FRAG: "More Fragments",
    FC_FLAG_RETRY: "Retry",
    FC_FLAG_PWR_MGT: "Power Management",
    FC_FLAG_MORE_DATA: "More Data",
    FC_FLAG_PROTECTED: "Protected",
    FC_FLAG_ORDER: "Order"
}


class WiFi(BaseLayer):

    def __init__(self, version: int = FRAME_VERSION_80211,
                 frame_type: int = 0,
                 subtype: int = SUB_TYPE_DATA,
                 flags: int = 0,
                 duration: int = 0,
                 addr1: bytes = b'\x00' * 6,
                 addr2: bytes = b'\x00' * 6,
                 addr3: bytes = b'\x00' * 6,
                 seq_control: int = 0,
                 addr4: bytes = b'\x00' * 6,
                 qos_control: int = 0,
                 ht_control: int = 0):
        super().__init__()
        self.version = version & 0x03
        self.frame_type = frame_type & 0x03
        self.subtype = subtype & 0x0F
        self.flags = flags & 0xFF
        self.duration = duration
        self.addr1 = addr1
        self.addr2 = addr2
        self.addr3 = addr3
        self.seq_control = seq_control
        self.addr4 = addr4
        self.qos_control = qos_control
        self.ht_control = ht_control

    def _build_frame_control(self) -> int:
        """Build the Frame Control field from separate fields."""
        fc = 0
        fc |= self.version & 0x03
        fc |= (self.frame_type & 0x03) << 2
        fc |= (self.subtype & 0x0F) << 4
        fc |= (self.flags & 0xFF) << 8
        return fc

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        if self.subtype == 0:
            layer = self.payload.__class__.__name__
            if layer == 'Beacon':
                self.subtype = SUB_TYPE_BEACON
            elif layer == 'ProbeRequest':
                self.subtype = SUB_TYPE_PROBE_REQ
            elif layer == 'ProbeResponse':
                self.subtype = SUB_TYPE_PROBE_RSP
            else:
                self.subtype = SUB_TYPE_DATA

        frame_control = self._build_frame_control()

        result = struct.pack('<HH', frame_control, self.duration)
        result += self.addr1
        result += self.addr2
        result += self.addr3
        result += struct.pack('<H', self.seq_control)

        to_ds = bool(self.flags & FC_FLAG_TO_DS)
        from_ds = bool(self.flags & FC_FLAG_FROM_DS)
        has_addr4 = to_ds and from_ds

        if has_addr4:
            result += self.addr4

        if self.frame_type == FRAME_TYPE_DATA and (self.subtype & 0x08):
            result += struct.pack('<H', self.qos_control)

        if self.flags & FC_FLAG_ORDER:
            result += struct.pack('<I', self.ht_control)

        if payload_bytes:
            result += payload_bytes
        return result

    def __len__(self):
        total = 24
        to_ds = bool(self.flags & FC_FLAG_TO_DS)
        from_ds = bool(self.flags & FC_FLAG_FROM_DS)
        if to_ds and from_ds:
            total += 6
        if self.frame_type == FRAME_TYPE_DATA and (self.subtype & 0x08):
            total += 2
        if self.flags & FC_FLAG_ORDER:
            total += 4
        if self.payload:
            total += len(self.payload)
        elif self._raw_payload:
            total += len(self._raw_payload)
        return total

    def __repr__(self):
        return (f"<WiFi version={self.version} ({self.get_version_name()}), "
                f"type={self.frame_type} ({self.get_frame_type_name()}), "
                f"subtype={self.subtype} ({self.get_subtype_name()}), "
                f"flags=0x{self.flags:04x}>")

    def copy(self) -> 'WiFi':
        new_layer = WiFi(
            version=self.version,
            frame_type=self.frame_type,
            subtype=self.subtype,
            flags=self.flags,
            duration=self.duration,
            addr1=self.addr1,
            addr2=self.addr2,
            addr3=self.addr3,
            seq_control=self.seq_control,
            addr4=self.addr4,
            qos_control=self.qos_control,
            ht_control=self.ht_control
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"version={self.version} ({self.get_version_name()})",
            f"frame_type={self.frame_type} ({self.get_frame_type_name()})",
            f"subtype={self.subtype} ({self.get_subtype_name()})",
            f"flags=0x{self.flags:04x} ({self.get_flags_list()})",
            f"duration=0x{self.duration:04x}",
            f"addr1={self.addr1.hex(':')}",
            f"addr2={self.addr2.hex(':')}",
            f"addr3={self.addr3.hex(':')}",
            f"seq_control=0x{self.seq_control:04x}",
        ]
        to_ds = bool(self.flags & FC_FLAG_TO_DS)
        from_ds = bool(self.flags & FC_FLAG_FROM_DS)
        if to_ds and from_ds:
            fields.append(f"addr4={self.addr4.hex(':')}")
        if self.frame_type == FRAME_TYPE_DATA and (self.subtype & 0x08):
            fields.append(f"qos_control=0x{self.qos_control:04x}")
        if self.flags & FC_FLAG_ORDER:
            fields.append(f"ht_control=0x{self.ht_control:08x}")
        return fields

    def get_version_name(self) -> str:
        return FRAME_VERSION_NAMES.get(self.version, "Unknown")

    def get_frame_type(self) -> int:
        return self.frame_type

    def get_frame_type_name(self) -> str:
        return FRAME_TYPE_NAMES.get(self.frame_type, "Unknown")

    def get_subtype(self) -> int:
        return self.subtype

    def get_subtype_name(self) -> str:
        if self.frame_type == FRAME_TYPE_MANAGEMENT:
            return MANAGEMENT_SUBTYPE_NAMES.get(self.subtype, f"Unknown(0x{self.subtype:x})")
        elif self.frame_type == FRAME_TYPE_CONTROL:
            return CONTROL_SUBTYPE_NAMES.get(self.subtype, f"Unknown(0x{self.subtype:x})")
        elif self.frame_type == FRAME_TYPE_DATA:
            return DATA_SUBTYPE_NAMES.get(self.subtype, f"Unknown(0x{self.subtype:x})")
        return f"Unknown(0x{self.subtype:x})"

    def get_flags(self) -> dict:
        return {
            'to_ds': bool(self.flags & FC_FLAG_TO_DS),
            'from_ds': bool(self.flags & FC_FLAG_FROM_DS),
            'more_frag': bool(self.flags & FC_FLAG_MORE_FRAG),
            'retry': bool(self.flags & FC_FLAG_RETRY),
            'pwr_mgt': bool(self.flags & FC_FLAG_PWR_MGT),
            'more_data': bool(self.flags & FC_FLAG_MORE_DATA),
            'protected': bool(self.flags & FC_FLAG_PROTECTED),
            'order': bool(self.flags & FC_FLAG_ORDER)
        }

    def get_flags_list(self) -> str:
        enabled = []
        if self.flags & FC_FLAG_TO_DS:
            enabled.append("To DS")
        if self.flags & FC_FLAG_FROM_DS:
            enabled.append("From DS")
        if self.flags & FC_FLAG_MORE_FRAG:
            enabled.append("More Frag")
        if self.flags & FC_FLAG_RETRY:
            enabled.append("Retry")
        if self.flags & FC_FLAG_PWR_MGT:
            enabled.append("Pwr Mgt")
        if self.flags & FC_FLAG_MORE_DATA:
            enabled.append("More Data")
        if self.flags & FC_FLAG_PROTECTED:
            enabled.append("Protected")
        if self.flags & FC_FLAG_ORDER:
            enabled.append("Order")
        return ", ".join(enabled) if enabled else "None"

    def get_ds_mode(self) -> str:
        to_ds = bool(self.flags & FC_FLAG_TO_DS)
        from_ds = bool(self.flags & FC_FLAG_FROM_DS)
        if to_ds and from_ds:
            return "WDS (4-address)"
        elif to_ds:
            return "To DS"
        elif from_ds:
            return "From DS"
        return "Direct (no DS)"

    def get_sequence_number(self) -> int:
        return (self.seq_control >> 4) & 0x0FFF

    def get_fragment_number(self) -> int:
        return self.seq_control & 0x000F

    def set_flag(self, flag: int, enabled: bool = True):
        """Enable or disable a specific frame control flag."""
        if enabled:
            self.flags |= flag
        else:
            self.flags &= ~flag

    def is_management(self) -> bool:
        return self.frame_type == FRAME_TYPE_MANAGEMENT

    def is_control(self) -> bool:
        return self.frame_type == FRAME_TYPE_CONTROL

    def is_data(self) -> bool:
        return self.frame_type == FRAME_TYPE_DATA

    def is_beacon(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_BEACON

    def is_probe_request(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_PROBE_REQ

    def is_probe_response(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_PROBE_RSP

    def is_assoc_request(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_ASSOC_REQ

    def is_assoc_response(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_ASSOC_RSP

    def is_auth(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_AUTH

    def is_deauth(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_DEAUTH

    def is_disassoc(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_DISASSOC

    def is_action(self) -> bool:
        return self.is_management() and self.subtype == SUB_TYPE_ACTION

    def is_ack(self) -> bool:
        return self.is_control() and self.subtype == SUB_TYPE_ACK

    def is_rts(self) -> bool:
        return self.is_control() and self.subtype == SUB_TYPE_RTS

    def is_cts(self) -> bool:
        return self.is_control() and self.subtype == SUB_TYPE_CTS

    def is_qos_data(self) -> bool:
        return self.is_data() and (self.subtype & 0x08)

    def is_data_frame(self) -> bool:
        return self.is_data() and (self.subtype & 0x08) == 0

    def get_address_1(self) -> bytes:
        return self.addr1

    def get_address_2(self) -> bytes:
        return self.addr2

    def get_address_3(self) -> bytes:
        return self.addr3

    def get_address_4(self) -> bytes:
        return self.addr4

    def get_ra(self) -> bytes:
        return self.addr1

    def get_ta(self) -> bytes:
        return self.addr2

    def get_da(self) -> bytes:
        to_ds = bool(self.flags & FC_FLAG_TO_DS)
        from_ds = bool(self.flags & FC_FLAG_FROM_DS)
        if to_ds and not from_ds:
            return self.addr3
        elif from_ds and not to_ds:
            return self.addr1
        return self.addr3

    def get_sa(self) -> bytes:
        to_ds = bool(self.flags & FC_FLAG_TO_DS)
        from_ds = bool(self.flags & FC_FLAG_FROM_DS)
        if to_ds and not from_ds:
            return self.addr2
        elif from_ds and not to_ds:
            return self.addr3
        return self.addr2

    def get_bssid(self) -> bytes:
        return self.addr3


DATA_LINK_TYPE_ETHERNET = 1
DATA_LINK_TYPE_DOT3 = 2
DATA_LINK_TYPE_PPP = 3
DATA_LINK_TYPE_80211 = 4
DATA_LINK_TYPE_UNKNOWN = 0

DATA_LINK_TYPE_NAMES = {
    1: "Ethernet",
    2: "Dot3 (802.3)",
    3: "PPP",
    4: "802.11 Wi-Fi"
}


def detect_data_link_type(packet_bytes: bytes) -> int:
    """Detect data link type from raw packet bytes."""
    if len(packet_bytes) < 2:
        return DATA_LINK_TYPE_UNKNOWN

    fc_byte = packet_bytes[0]
    fc_version = fc_byte & 0x03

    if fc_version == 0x00:
        frame_type = (fc_byte >> 2) & 0x03
        if frame_type in (0x00, 0x01, 0x02, 0x03):
            return DATA_LINK_TYPE_80211

    if len(packet_bytes) >= 14:
        ether_type = struct.unpack('!H', packet_bytes[12:14])[0]
        if ether_type >= 0x0600:
            return DATA_LINK_TYPE_ETHERNET
        elif ether_type <= 0x05DC:
            return DATA_LINK_TYPE_DOT3

    if len(packet_bytes) >= 2:
        if packet_bytes[0] == 0xFF and packet_bytes[1] == 0x03:
            return DATA_LINK_TYPE_PPP

    return DATA_LINK_TYPE_UNKNOWN


def is_wifi_packet(packet_bytes: bytes) -> bool:
    return detect_data_link_type(packet_bytes) == DATA_LINK_TYPE_80211


def is_ethernet_packet(packet_bytes: bytes) -> bool:
    return detect_data_link_type(packet_bytes) == DATA_LINK_TYPE_ETHERNET


def is_dot3_packet(packet_bytes: bytes) -> bool:
    return detect_data_link_type(packet_bytes) == DATA_LINK_TYPE_DOT3


def is_ppp_packet(packet_bytes: bytes) -> bool:
    return detect_data_link_type(packet_bytes) == DATA_LINK_TYPE_PPP


def get_data_link_type_name(dlt_type: int) -> str:
    return DATA_LINK_TYPE_NAMES.get(dlt_type, "Unknown")


class WiFiParser:

    @staticmethod
    def load_as_wifi_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 24:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="802.11 frame requires at least 24 bytes")

        frame_control, duration = struct.unpack('<HH', data[:4])

        version = frame_control & 0x0003
        frame_type = (frame_control >> 2) & 0x0003
        subtype = (frame_control >> 4) & 0x000F
        flags = (frame_control >> 8) & 0xFF

        addr1 = data[4:10]
        addr2 = data[10:16]
        addr3 = data[16:22]
        seq_control = struct.unpack('<H', data[22:24])[0]

        offset = 24
        addr4 = b'\x00' * 6
        qos_control = 0
        ht_control = 0

        to_ds = bool(flags & FC_FLAG_TO_DS)
        from_ds = bool(flags & FC_FLAG_FROM_DS)
        has_addr4 = to_ds and from_ds

        if has_addr4 and len(data) >= offset + 6:
            addr4 = data[offset:offset + 6]
            offset += 6

        has_qos = (frame_type == FRAME_TYPE_DATA and (subtype & 0x08))

        if has_qos and len(data) >= offset + 2:
            qos_control = struct.unpack('<H', data[offset:offset + 2])[0]
            offset += 2

        has_ht = bool(flags & FC_FLAG_ORDER)
        if has_ht and len(data) >= offset + 4:
            ht_control = struct.unpack('<I', data[offset:offset + 4])[0]
            offset += 4

        wifi = WiFi(
            version=version,
            frame_type=frame_type,
            subtype=subtype,
            flags=flags,
            duration=duration,
            addr1=addr1,
            addr2=addr2,
            addr3=addr3,
            seq_control=seq_control,
            addr4=addr4,
            qos_control=qos_control,
            ht_control=ht_control
        )


        if verbose:
            print(f"\n{BOLD}802.11 WIFI LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}Frame Control:{CYAN} 0x{frame_control:04x}')
            print(f'   {BLUE}  Version:{CYAN} {version} ({FRAME_VERSION_NAMES.get(version, "Unknown")})')
            print(f'   {BLUE}  Type:{CYAN} {frame_type} ({FRAME_TYPE_NAMES.get(frame_type, "Unknown")})')
            print(f'   {BLUE}  Subtype:{CYAN} {subtype} ({wifi.get_subtype_name()})')
            print(f'   {BLUE}  Flags:{CYAN} 0x{flags:04x} ({wifi.get_flags_list()})')
            print(f'   {BLUE}Duration:{CYAN} 0x{duration:04x}')
            print(f'   {BLUE}Addr1 (RA):{CYAN} {addr1.hex(":")} ({'Multicast' if addr1.hex(":")[:2] in MC else OUI_MAP.get(addr1.hex(":").replace(":", "")[:6],'?')})')
            print(f'   {BLUE}Addr2 (TA):{CYAN} {addr2.hex(":")} ({'Multicast' if addr2.hex(":")[:2] in MC else OUI_MAP.get(addr2.hex(":").replace(":", "")[:6],'?')})')
            print(f'   {BLUE}Addr3 (BSSID):{CYAN} {addr3.hex(":")} ({'Multicast' if addr3.hex(":")[:2] in MC else OUI_MAP.get(addr3.hex(":").replace(":", "")[:6],'?')})')
            print(f'   {BLUE}Seq Control:{CYAN} 0x{seq_control:04x}')
            print(f'   {BLUE}  Fragment:{CYAN} {(seq_control & 0x000F)}')
            print(f'   {BLUE}  Sequence:{CYAN} {(seq_control >> 4) & 0x0FFF} {RESET}')
            if has_addr4:
                print(f'   {BLUE}Addr4:{CYAN} {addr4.hex(":")} ({'Multicast' if addr4[:2] in MC else OUI_MAP.get(str(addr4).replace(":", "").replace("'","")[:6],'?')}){RESET}')
            if has_qos:
                print(f'   {BLUE}QoS Control:{CYAN} 0x{qos_control:04x} {RESET}')
            if has_ht:
                print(f'   {BLUE}HT Control:{CYAN} 0x{ht_control:08x} {RESET}')

        if len(data) > offset:
            extra = data[offset:]
            if extra:
                if subtype == 8:
                    raw_layer = BeaconParser.load_as_beacon_layer(extra, verbose=verbose)
                    return wifi / raw_layer
                elif subtype == 4:
                    raw_layer = ProbeRequestParser.load_as_probe_request_layer(extra, verbose=verbose)
                    return wifi / raw_layer
                elif subtype == 5:
                    raw_layer = ProbeResponseParser.load_as_probe_response_layer(extra, verbose=verbose)
                    return wifi / raw_layer
                else:
                    from ..Raw import RawParser
                    raw_layer = RawParser.load_as_Raw_layer(extra, verbose=verbose)
                    return wifi / raw_layer

        return wifi

CAP_ESS = 0x0001
CAP_IBSS = 0x0002
CAP_PRIVACY = 0x0010
CAP_SHORT_PREAMBLE = 0x0020
CAP_SHORT_SLOT_TIME = 0x0400

CAP_NAMES = {
    0x0001: "ESS",
    0x0002: "IBSS",
    0x0010: "Privacy",
    0x0020: "Short Preamble",
    0x0400: "Short Slot Time"
}

IE_SSID = 0
IE_SUPPORTED_RATES = 1
IE_DS_PARAMETER_SET = 3
IE_TIM = 5
IE_COUNTRY = 7
IE_ERP = 42
IE_HT_CAPABILITIES = 45
IE_RSN = 48
IE_EXTENDED_SUPPORTED_RATES = 50
IE_HT_OPERATION = 61
IE_EXTENDED_CAPABILITIES = 127
IE_VHT_CAPABILITIES = 191
IE_VHT_OPERATION = 192
IE_VENDOR_SPECIFIC = 221

"""
802.11 Beacon Frame Implementation (class Beacon)
- IEEE 802.11-2020: Beacon frames are management frames used by APs to announce their presence
"""

class Beacon(BaseLayer):

    def __init__(self, timestamp: int = 0, beacon_interval: int = 100,
                 capability: int = CAP_ESS | CAP_SHORT_PREAMBLE):
        super().__init__()
        self.timestamp = timestamp
        self.beacon_interval = beacon_interval
        self.capability = capability

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        result = struct.pack('!QHH', self.timestamp, self.beacon_interval, self.capability)

        if payload_bytes:
            result += payload_bytes
        return result

    def __len__(self):
        total = 12
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        cap_str = self.get_capabilities_str()
        return (f"<Beacon interval={self.beacon_interval}ms, "
                f"cap=0x{self.capability:04x} [{cap_str}]>")

    def copy(self) -> 'Beacon':
        new_layer = Beacon(
            timestamp=self.timestamp,
            beacon_interval=self.beacon_interval,
            capability=self.capability,
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"timestamp={self.timestamp}",
            f"beacon_interval={self.beacon_interval}ms",
            f"capability=0x{self.capability:04x} [{self.get_capabilities_str()}]",
        ]
        return fields


    def get_capabilities_str(self) -> str:
        enabled = []
        for flag, name in CAP_NAMES.items():
            if self.capability & flag:
                enabled.append(name)
        return ", ".join(enabled) if enabled else "None"

    def is_ess(self) -> bool:
        return bool(self.capability & CAP_ESS)

    def is_ibss(self) -> bool:
        return bool(self.capability & CAP_IBSS)

    def has_privacy(self) -> bool:
        return bool(self.capability & CAP_PRIVACY)

    def has_short_preamble(self) -> bool:
        return bool(self.capability & CAP_SHORT_PREAMBLE)

    def has_short_slot_time(self) -> bool:
        return bool(self.capability & CAP_SHORT_SLOT_TIME)


class BeaconParser:
    """Parser for 802.11 Beacon frames."""

    @staticmethod
    def load_as_beacon_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 12:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="Beacon frame requires at least 12 bytes")

        timestamp, beacon_interval, capability = struct.unpack('!QHH', data[:12])
        ie_data = data[12:]

        beacon = Beacon(
            timestamp=timestamp,
            beacon_interval=beacon_interval,
            capability=capability,
        )

        if verbose:
            cap_str = beacon.get_capabilities_str()

            print(f"\n{BOLD}802.11 BEACON LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}Timestamp:{CYAN} {timestamp}')
            print(f'   {BLUE}Beacon Interval:{CYAN} {beacon_interval}ms')
            print(f'   {BLUE}Capability:{CYAN} 0x{capability:04x} [{cap_str}] {RESET}')

        if ie_data:
            ele = ElementParser.load_as_element_layer(ie_data,verbose=verbose)
            return beacon / ele

        return beacon

CIPHER_SUITES = {
    0: "Use group cipher suite",
    1: "WEP-40",
    2: "TKIP",
    3: "Reserved",
    4: "CCMP-128 (AES)",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    7: "Group addressed traffic not allowed",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

AKM_SUITES = {
    1: "802.1X (WPA2-Enterprise)",
    2: "PSK (WPA2-Personal)",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE (WPA3-Personal)",
    9: "FT-SAE",
    11: "802.1X-Suite-B (SHA256)",
    12: "802.1X-Suite-B-192 (SHA384)",
    13: "FT-802.1X-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "SAE-EXT-KEY",
}


class RSNParseError(ValueError):
    ...

def _suite_name(oui_type: bytes, table: dict) -> str:
    oui, suite_type = oui_type[:3], oui_type[3]
    name = table.get(suite_type, f"Unknown (0x{suite_type:02x})")
    if oui != b"\x00\x0f\xac":
        return f"Vendor-specific (OUI {oui.hex(':')}) - type {suite_type}"
    return name


def parse_rsn_ie(data: bytes) -> dict:
    if len(data) < 2:
        raise RSNParseError("Data too short to contain an IE header")

    offset = 0
    element_id = None
    if data[0] == 0x30:
        element_id, length = data[0], data[1]
        if length != len(data) - 2:
            raise RSNParseError(
                f"Length field ({length}) doesn't match payload size ({len(data) - 2})"
            )
        offset = 2

    body = data[offset:]
    pos = 0

    def take(n: int, what: str) -> bytes:
        nonlocal pos
        if pos + n > len(body):
            raise RSNParseError(f"Truncated while reading {what}")
        chunk = body[pos:pos + n]
        pos += n
        return chunk

    result = {"element_id": element_id}

    result["version"] = struct.unpack("<H", take(2, "version"))[0]

    group_cipher = take(4, "group cipher suite")
    result["group_cipher_suite"] = _suite_name(group_cipher, CIPHER_SUITES)

    pairwise_count = struct.unpack("<H", take(2, "pairwise cipher count"))[0]
    result["pairwise_cipher_suites"] = [
        _suite_name(take(4, "pairwise cipher suite"), CIPHER_SUITES)
        for _ in range(pairwise_count)
    ]

    akm_count = struct.unpack("<H", take(2, "AKM suite count"))[0]
    result["akm_suites"] = [
        _suite_name(take(4, "AKM suite"), AKM_SUITES) for _ in range(akm_count)
    ]

    if pos + 2 <= len(body):
        cap_raw = struct.unpack("<H", take(2, "RSN capabilities"))[0]
        result["rsn_capabilities"] = {
            "raw": cap_raw,
            "pre_auth": bool(cap_raw & 0x0001),
            "no_pairwise": bool(cap_raw & 0x0002),
            "ptksa_replay_counter": (cap_raw >> 2) & 0x03,
            "gtksa_replay_counter": (cap_raw >> 4) & 0x03,
            "mfp_required": bool(cap_raw & 0x0040),
            "mfp_capable": bool(cap_raw & 0x0080),
            "joint_multi_band_rsna": bool(cap_raw & 0x0100),
            "peerkey_enabled": bool(cap_raw & 0x0200),
            "extended_key_id": bool(cap_raw & 0x2000),
        }

    if pos + 2 <= len(body):
        pmkid_count = struct.unpack("<H", take(2, "PMKID count"))[0]
        result["pmkid_list"] = [take(16, "PMKID").hex() for _ in range(pmkid_count)]

    if pos + 4 <= len(body):
        group_mgmt = take(4, "group management cipher suite")
        result["group_mgmt_cipher_suite"] = _suite_name(group_mgmt, CIPHER_SUITES)

    if pos != len(body):
        result["trailing_bytes"] = body[pos:].hex()

    return result

HT_CAPABILITY_INFO_LDPC = 0x0001
HT_CAPABILITY_INFO_40MHZ = 0x0002
HT_CAPABILITY_INFO_SM_POWER_SAVE_MASK = 0x000C
HT_CAPABILITY_INFO_GREEN_FIELD = 0x0010
HT_CAPABILITY_INFO_SHORT_GI_20 = 0x0020
HT_CAPABILITY_INFO_SHORT_GI_40 = 0x0040
HT_CAPABILITY_INFO_TX_STBC = 0x0080
HT_CAPABILITY_INFO_RX_STBC_MASK = 0x0300
HT_CAPABILITY_INFO_DELAYED_BA = 0x0400
HT_CAPABILITY_INFO_MAX_AMSDU = 0x0800
HT_CAPABILITY_INFO_DSSS_CCK_40 = 0x1000
HT_CAPABILITY_INFO_40MHZ_INTOLERANT = 0x2000
HT_CAPABILITY_INFO_L_SIG_TXOP = 0x4000

AMPDU_MAX_LENGTH_MASK = 0x03
AMPDU_MIN_MPDU_SPACING_MASK = 0x1C
IE_HT_OPERATION = 61

def parse_ht_operation_ie(data: bytes) -> dict:
    if len(data) < 22:
        raise ValueError(f"HT Operation requires 22 bytes, got {len(data)}")

    offset = 0
    primary_channel = data[offset]; offset += 1
    secondary_offset = data[offset]; offset += 1
    sta_channel_width = data[offset]; offset += 1
    rifs_mode = data[offset]; offset += 1
    ht_protection = data[offset]; offset += 1
    non_gf_present = data[offset]; offset += 1
    obss_non_gf_present = data[offset]; offset += 1
    dual_beacon = data[offset]; offset += 1
    dual_cts_protection = data[offset]; offset += 1
    stbc_beacon = data[offset]; offset += 1
    l_sig_txop_protection = data[offset]; offset += 1
    pco_active = data[offset]; offset += 1
    pco_phase = data[offset]; offset += 1
    reserved = data[offset:offset+7]; offset += 7
    basic_mcs_set = struct.unpack('<H', data[offset:offset+2])[0]; offset += 2

    basic_mcs_list = []
    for mcs in range(16):
        if basic_mcs_set & (1 << mcs):
            basic_mcs_list.append(mcs)

    secondary_names = {0: "None", 1: "Above", 3: "Below"}
    protection_names = {
        0: "No protection",
        1: "Non-member",
        2: "20 MHz",
        3: "Non-HT mixed"
    }

    return {
        "primary_channel": primary_channel,
        "secondary_channel_offset": {
            "raw": secondary_offset,
            "name": secondary_names.get(secondary_offset, f"Unknown ({secondary_offset})")
        },
        "sta_channel_width": {
            "raw": sta_channel_width,
            "name": "40 MHz" if sta_channel_width == 1 else "20 MHz"
        },
        "rifs_mode": bool(rifs_mode),
        "ht_protection": {
            "raw": ht_protection,
            "name": protection_names.get(ht_protection, f"Unknown ({ht_protection})")
        },
        "non_gf_present": bool(non_gf_present),
        "obss_non_gf_present": bool(obss_non_gf_present),
        "dual_beacon": bool(dual_beacon),
        "dual_cts_protection": bool(dual_cts_protection),
        "stbc_beacon": bool(stbc_beacon),
        "l_sig_txop_protection": bool(l_sig_txop_protection),
        "pco_active": bool(pco_active),
        "pco_phase": bool(pco_phase),
        "reserved": reserved.hex(),
        "basic_mcs_set": {
            "raw": basic_mcs_set,
            "mcs_list": basic_mcs_list
        }
    }

def parse_ht_capabilities_ie(data: bytes) -> dict:
    if len(data) < 26:
        raise ValueError("HT Capabilities must be exactly 26 bytes")

    offset = 0

    cap_info = struct.unpack('<H', data[offset:offset + 2])[0]
    offset += 2

    ampdu_params = data[offset]
    offset += 1

    mcs_set = data[offset:offset + 16]
    offset += 16

    ht_extended = struct.unpack('<H', data[offset:offset + 2])[0]
    offset += 2

    tx_beamforming = data[offset:offset + 4]
    offset += 4

    asel = data[offset]
    offset += 1

    supported_mcs = []
    for i in range(77):
        byte_idx = i // 8
        bit_idx = i % 8
        if byte_idx < len(mcs_set) and (mcs_set[byte_idx] & (1 << bit_idx)):
            supported_mcs.append(i)

    sm_power_save = (cap_info >> 2) & 0x03
    sm_names = {0: "Static", 1: "Dynamic", 2: "Reserved", 3: "Disabled"}

    rx_stbc = (cap_info >> 8) & 0x03

    max_ampdu = ampdu_params & AMPDU_MAX_LENGTH_MASK
    ampdu_lengths = {0: "8k", 1: "16k", 2: "32k", 3: "64k"}
    min_spacing = (ampdu_params & AMPDU_MIN_MPDU_SPACING_MASK) >> 2
    spacing_names = {
        0: "No restriction", 1: "1/4 µs", 2: "1/2 µs",
        3: "1 µs", 4: "2 µs", 5: "4 µs", 6: "8 µs", 7: "16 µs"
    }

    return {
        "capability_info": {
            "raw": cap_info,
            "ldpc": bool(cap_info & HT_CAPABILITY_INFO_LDPC),
            "forty_mhz": bool(cap_info & HT_CAPABILITY_INFO_40MHZ),
            "sm_power_save": sm_names.get(sm_power_save, "Unknown"),
            "green_field": bool(cap_info & HT_CAPABILITY_INFO_GREEN_FIELD),
            "short_gi_20": bool(cap_info & HT_CAPABILITY_INFO_SHORT_GI_20),
            "short_gi_40": bool(cap_info & HT_CAPABILITY_INFO_SHORT_GI_40),
            "tx_stbc": bool(cap_info & HT_CAPABILITY_INFO_TX_STBC),
            "rx_stbc": rx_stbc,
            "delayed_ba": bool(cap_info & HT_CAPABILITY_INFO_DELAYED_BA),
            "max_amsdu": bool(cap_info & HT_CAPABILITY_INFO_MAX_AMSDU),
            "dsss_cck_40": bool(cap_info & HT_CAPABILITY_INFO_DSSS_CCK_40),
            "forty_mhz_intolerant": bool(cap_info & HT_CAPABILITY_INFO_40MHZ_INTOLERANT),
            "l_sig_txop": bool(cap_info & HT_CAPABILITY_INFO_L_SIG_TXOP),
        },
        "ampdu_params": {
            "raw": ampdu_params,
            "max_ampdu_length": ampdu_lengths.get(max_ampdu, "Unknown"),
            "min_mpdu_spacing": spacing_names.get(min_spacing, "Unknown"),
        },
        "mcs_set": {
            "raw": mcs_set.hex(),
            "supported_mcs": supported_mcs,
        },
        "ht_extended": {
            "raw": ht_extended,
        },
        "tx_beamforming": {
            "raw": tx_beamforming.hex(),
        },
        "asel": {
            "raw": asel,
        }
    }

class Element(BaseLayer):
    def __init__(self,
                 ie_id:int = 0,
                 lenght: int = 0,
                 data:bytes = b'Light-AP'):
        super().__init__()
        self.ie_id = ie_id
        self.lenght = lenght
        self.data = data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        if self.lenght == 0:
            self.lenght = len(self.data)

        result = struct.pack('!BB', self.ie_id, self.lenght)
        result += self.data

        if payload_bytes:
            result += payload_bytes
        return result

    def __len__(self):
        return self.lenght

    def __repr__(self):
        return (f"<Element ie_id={self.ie_id}, "
                f"lenght={self.lenght}, data={self.data}>")

    def copy(self) -> 'Element':
        new_layer = Element(
            ie_id=self.ie_id,
            lenght=self.lenght,
            data=self.data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"ie_id={self.ie_id}",
            f"lenght={self.lenght}ms",
            f"data={self.data} ]",
        ]
        return fields

class ElementParser:

    @staticmethod
    def load_as_element_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 3:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="Element data requires at least 3 bytes")

        ie_id,lenght = struct.unpack('!BB', data[:2])

        element = Element(
            ie_id=ie_id,
            lenght=lenght,
            data=data[2:lenght + 2]
        )
        if verbose:
            ssid = ""
            if ie_id == IE_SSID:
                if lenght >= 3 and ie_id == IE_SSID:
                    try:
                        ssid = data[2:lenght + 2].decode('utf-8', errors='ignore')
                    except:
                        ssid = str(data[2:lenght + 2])
                    pass

            channel = 0
            if ie_id == IE_DS_PARAMETER_SET:
                if lenght >= 1 and ie_id == IE_DS_PARAMETER_SET:
                    channel = data[2:lenght + 2]

            rates = []
            if ie_id == 1:
                if lenght < 3:
                    pass
                if ie_id in (1, 50):
                    for i in range(lenght):
                        val = data[2 + i]
                        rate = (val & 0x7f) / 2.0
                        basic = bool(val & 0x80)
                        rates.append((rate, basic))

            rsn = None
            if lenght >= 3 and ie_id == IE_RSN :
                rsn = parse_rsn_ie(data[2:lenght + 2])

            print(f"\n{BOLD}802.11 BEACON ELEMENT : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f"   {BLUE}ID:{CYAN} {ie_id}")
            print(f"   {BLUE}LEN:{CYAN} {lenght} {RESET}")

            if ssid:
                print(f'   {BLUE}SSID:{CYAN} "{ssid}" {RESET}')
            elif channel:
                print(f'   {BLUE}Channel:{CYAN} {channel[0]} {RESET}')
            elif rates:
                print(f'   {BLUE}Rates:{CYAN} {rates} [Mbit/sec]{RESET}')
            elif rsn:
                print(f"   {BLUE}RSN Information:{CYAN} ")
                print(f"     {BLUE}Version:{CYAN} {rsn['version']}")
                print(f"     {BLUE}Group Cipher:{CYAN} {rsn['group_cipher_suite']}")
                print(f"     {BLUE}Pairwise Ciphers:{CYAN} {', '.join(rsn['pairwise_cipher_suites'])}")
                print(f"     {BLUE}AKM Suites:{CYAN}  {', '.join(rsn['akm_suites'])}")
                print(f"     {BLUE}Capabilities:{CYAN}")
                print(f"       {BLUE}PRE AUTH:{CYAN} {rsn['rsn_capabilities']['pre_auth']}")
                print(f"       {BLUE}NO PAIRWISE:{CYAN} {rsn['rsn_capabilities']['no_pairwise']}")
                print(f"       {BLUE}MFP Capable:{CYAN} {rsn['rsn_capabilities']['mfp_capable']}")
                print(f"       {BLUE}MFP Required:{CYAN} {rsn['rsn_capabilities']['mfp_required']}")
                print(f"       {BLUE}PTKSA COUNTER:{CYAN} {rsn['rsn_capabilities']['ptksa_replay_counter']}")
                print(f"       {BLUE}GTKSA COUNTER:{CYAN} {rsn['rsn_capabilities']['gtksa_replay_counter']}")
                print(f"       {BLUE}PEER KEY{CYAN} {rsn['rsn_capabilities']['peerkey_enabled']}")
                print(f"       {BLUE}MULTIBAND RSNA:{CYAN} {rsn['rsn_capabilities']['joint_multi_band_rsna']}")
                print(f"       {BLUE}EXT KEY ID:{CYAN} {rsn['rsn_capabilities']['extended_key_id']} {RESET}")
            elif ie_id == IE_HT_CAPABILITIES:
                if lenght >= 26:
                    ht_cap = parse_ht_capabilities_ie(data[2:lenght + 2])
                    print(f"   {BLUE}HT Capabilities (802.11n):{CYAN}")
                    cap = ht_cap['capability_info']
                    print(f"     {BLUE}Capability Info:{CYAN} 0x{cap['raw']:04x}")
                    print(f"       {BLUE}LDPC Coding:{CYAN} {cap['ldpc']}")
                    print(f"       {BLUE}40 MHz Support:{CYAN} {cap['forty_mhz']}")
                    print(f"       {BLUE}SM Power Save:{CYAN} {cap['sm_power_save']}")
                    print(f"       {BLUE}Green Field Preamble:{CYAN} {cap['green_field']}")
                    print(f"       {BLUE}Short GI (20 MHz):{CYAN} {cap['short_gi_20']}")
                    print(f"       {BLUE}Short GI (40 MHz):{CYAN} {cap['short_gi_40']}")
                    print(f"       {BLUE}Tx STBC:{CYAN} {cap['tx_stbc']}")
                    print(f"       {BLUE}Rx STBC:{CYAN} {cap['rx_stbc']} (0=No, 1=1stream, 2=2streams, 3=3streams)")
                    print(f"       {BLUE}Delayed Block Ack:{CYAN} {cap['delayed_ba']}")
                    print(f"       {BLUE}Max A-MSDU:{CYAN} {cap['max_amsdu']} (0=3839, 1=7935 bytes)")
                    print(f"       {BLUE}DSSS/CCK in 40MHz:{CYAN} {cap['dsss_cck_40']}")
                    print(f"       {BLUE}40MHz Intolerant:{CYAN} {cap['forty_mhz_intolerant']}")
                    print(f"       {BLUE}L-SIG TXOP Protection:{CYAN} {cap['l_sig_txop']}")
                    ampdu = ht_cap['ampdu_params']
                    print(f"     {BLUE}AMPDU Parameters:{CYAN} 0x{ampdu['raw']:02x}")
                    print(f"       {BLUE}Max AMPDU Length:{CYAN} {ampdu['max_ampdu_length']}")
                    print(f"       {BLUE}Min MPDU Spacing:{CYAN} {ampdu['min_mpdu_spacing']}")
                    mcs = ht_cap['mcs_set']
                    print(f"     {BLUE}Supported MCS Set:{CYAN} (Raw: {mcs['raw']})")
                    mcs_list = mcs['supported_mcs']
                    if mcs_list:
                        chunks = []
                        for i in range(0, 77, 8):
                            chunk = [str(x) for x in mcs_list if i <= x < i + 8]
                            if chunk:
                                chunks.append(f"MCS{i}-{i + 7}: " + ", ".join(chunk) if chunk else "None")
                        print(f"       {BLUE}Supported:{CYAN} {mcs_list}")

                        ranges = []
                        if mcs_list:
                            start = mcs_list[0]
                            end = start
                            for m in mcs_list[1:]:
                                if m == end + 1:
                                    end = m
                                else:
                                    ranges.append(f"{start}-{end}" if start != end else str(start))
                                    start = m
                                    end = m
                            ranges.append(f"{start}-{end}" if start != end else str(start))
                            print(f"       {BLUE}MCS Ranges:{CYAN} {', '.join(ranges)}")
                    else:
                        print(f"       {BLUE}Supported:{CYAN} None")

                    ht_ext = ht_cap['ht_extended']
                    print(f"     {BLUE}HT Extended Capabilities:{CYAN} 0x{ht_ext['raw']:04x}")
                    tx_bf = ht_cap['tx_beamforming']
                    print(f"     {BLUE}Transmit Beamforming:{CYAN} {tx_bf['raw']}")
                    asel = ht_cap['asel']
                    print(f"     {BLUE}Antenna Selection (ASEL):{CYAN} 0x{asel['raw']:02x}")
                    print(RESET)
            elif ie_id == IE_HT_OPERATION:
                if lenght >= 22:
                    ht_op = parse_ht_operation_ie(data[2:lenght + 2])
                    print(f"   {BLUE}HT Operation (802.11n):{CYAN}")
                    print(f"     {BLUE}Primary Channel:{CYAN} {ht_op['primary_channel']}")
                    print(f"     {BLUE}Secondary Offset:{CYAN} {ht_op['secondary_channel_offset']['name']} ({ht_op['secondary_channel_offset']['raw']})")
                    print(f"     {BLUE}Channel Width:{CYAN} {ht_op['sta_channel_width']['name']}")
                    print(f"     {BLUE}RIFS Mode:{CYAN} {ht_op['rifs_mode']}")
                    print(f"     {BLUE}HT Protection:{CYAN} {ht_op['ht_protection']['name']}")
                    print(f"     {BLUE}Non-GF Present:{CYAN} {ht_op['non_gf_present']}")
                    print(f"     {BLUE}OBSS Non-GF Present:{CYAN} {ht_op['obss_non_gf_present']}")
                    print(f"     {BLUE}Dual Beacon:{CYAN} {ht_op['dual_beacon']}")
                    print(f"     {BLUE}Dual CTS Protection:{CYAN} {ht_op['dual_cts_protection']}")
                    print(f"     {BLUE}STBC Beacon:{CYAN} {ht_op['stbc_beacon']}")
                    print(f"     {BLUE}L-SIG TXOP Protection:{CYAN} {ht_op['l_sig_txop_protection']}")
                    print(f"     {BLUE}PCO Active:{CYAN} {ht_op['pco_active']}")
                    print(f"     {BLUE}PCO Phase:{CYAN} {ht_op['pco_phase']}")
                    print(f"     {BLUE}Basic MCS Set:{CYAN} {ht_op['basic_mcs_set']['mcs_list']} (raw: 0x{ht_op['basic_mcs_set']['raw']:04x})")
                    print(RESET)
            else:
                print(f"     {BLUE}DATA:{CYAN} {data[2:lenght + 2]} {RESET}")

        if len(data) > lenght and data[lenght+2:] != b'':
            raw = ElementParser.load_as_element_layer(data[lenght+2:], verbose=verbose)
            return element / raw

        return element

"""
Probe Request Frame (Subtype 4)
"""

class ProbeRequest(BaseLayer):
    def __init__(self):
        super().__init__()

    def build(self) -> bytes:
        """Build the Probe Request body (just the payload/tags)."""
        return self.get_payload_bytes()

    def __len__(self):
        return len(self.get_payload_bytes())

    def __repr__(self):
        return "<ProbeRequest>"

    def copy(self) -> 'ProbeRequest':
        new_layer = ProbeRequest()
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return []


"""
Probe Response Frame (Subtype 5)
"""

class ProbeResponse(BaseLayer):
    def __init__(self, timestamp: int = 0, beacon_interval: int = 100,
                 capability: int = 0x0011):
        super().__init__()
        self.timestamp = timestamp
        self.beacon_interval = beacon_interval
        self.capability = capability

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        result = struct.pack('!QHH', self.timestamp, self.beacon_interval, self.capability)

        if payload_bytes:
            result += payload_bytes
        return result

    def __len__(self):
        return 12 + len(self.get_payload_bytes())

    def __repr__(self):
        cap_str = self.get_capabilities_str()
        return f"<ProbeResponse interval={self.beacon_interval}ms, cap=0x{self.capability:04x} [{cap_str}]>"

    def copy(self) -> 'ProbeResponse':
        new_layer = ProbeResponse(
            timestamp=self.timestamp,
            beacon_interval=self.beacon_interval,
            capability=self.capability,
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"timestamp={self.timestamp}",
            f"beacon_interval={self.beacon_interval}ms",
            f"capability=0x{self.capability:04x} [{self.get_capabilities_str()}]",
        ]

    def get_capabilities_str(self) -> str:
        enabled = []
        for flag, name in CAP_NAMES.items():
            if self.capability & flag:
                enabled.append(name)
        return ", ".join(enabled) if enabled else "None"

    def is_ess(self) -> bool:
        return bool(self.capability & CAP_ESS)

    def is_ibss(self) -> bool:
        return bool(self.capability & CAP_IBSS)

    def has_privacy(self) -> bool:
        return bool(self.capability & CAP_PRIVACY)

class ProbeRequestParser:
    @staticmethod
    def load_as_probe_request_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        probe_req = ProbeRequest()

        if verbose:
            print(f"\n{BOLD}802.11 PROBE REQUEST : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}....{CYAN} .... {RESET}')

        if len(data) > 0:
            raw_layer = ElementParser.load_as_element_layer(data, verbose=verbose)
            return probe_req / raw_layer

        return probe_req

class ProbeResponseParser:
    @staticmethod
    def load_as_probe_response_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 12:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="Probe Response requires at least 12 bytes")

        timestamp, beacon_interval, capability = struct.unpack('!QHH', data[:12])
        ie_data = data[12:]

        probe_resp = ProbeResponse(
            timestamp=timestamp,
            beacon_interval=beacon_interval,
            capability=capability,
        )

        if verbose:
            cap_str = probe_resp.get_capabilities_str()
            print(f"\n{BOLD}802.11 PROBE RESPONSE : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}Timestamp:{CYAN} {timestamp}')
            print(f'   {BLUE}Beacon Interval:{CYAN} {beacon_interval}ms')
            print(f'   {BLUE}Capability:{CYAN} 0x{capability:04x} [{cap_str}] {RESET}')

        if ie_data:
            raw_layer = ElementParser.load_as_element_layer(ie_data, verbose=verbose)
            return probe_resp / raw_layer

        return probe_resp