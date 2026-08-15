# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from .Stp import *
from .Hex import *
from .EthernetII import *
from .isl import *
from .ppp import *
from .Arp import *
from .Dot3 import *
from .Vlan import *
from .LLC import *
from .Snap import *
from .Raw import *
from .hepler.ls import *
from .utils.CIDR import *
from .Layers.IS_LLC import *
from .Layers.get_layers import *
from .Interfaces.LinuxInterfaces import *
from .Layers.L2SocketL import *
from .Interfaces.LibpcapInterfacesLin import *
from .BaseLayer import *
from .Layers.Mac import *
from .Layers.IPtoa import *
from .Version import *
from .BaseLayer import *
from .Detect_layer import *
from .Logger.LightLogger import *
from .Logger.Errors import *
from .Consts import *

def Ethernet(src: Union[str, bytes] = None, dst: Union[str, bytes] = BROADCAST_MAC,
          ethertype: Union[str, bytes] = None) -> EthernetLayer:

    if src is None:
        src = get_default_interface_mac_linux()

    return EthernetLayer(dst=dst, src=src, ethertype=ethertype)

def PPP(address=0xFF, control=0x03, proto=0x0021):
    return PPPLayer(address=address, control=control, proto=proto)

def PPP2b(proto=0x0021):
    return PPP2bLayer(proto=proto)

def PPPoE(version=0x1, type=0x1, code=0x00,ssid=0x0000,lenght=0):
    return PPPoELayer(version=version, type=type, code=code, ssid=ssid, lenght=lenght)

def ISL(vlan_id: int = 100,type_code: int = ISL_TYPE_ETHERNET,user_priority: int = ISL_USER_NORMAL,
        src: Optional[str] = None,dst: str = ISL_DST_MAC_1,bpdu: int = 1,index: int = 0,
        reserved: int = 0) -> ISLLayer:

    if src is None:
        src = get_default_interface_mac_linux()

    return ISLLayer(vlan_id,type_code,user_priority,src,dst,bpdu=bpdu,index=index,reserved=reserved)

def ARP(hwtype: int = None, ptype: int = None, maclen: int = None,
        plen: int = None, opcode: int = None, macsrc: Union[str, bytes] = None,
        ipsrc: str = None, macdst: Union[str, bytes] = None, ipdst: str = None) -> ArpLayer:

    if macsrc is None:
        macsrc = get_default_interface_mac_linux()
    if macdst is None:
        macdst = BROADCAST_MAC
    if hwtype is None:
        hwtype = 1
    if ptype is None:
        ptype = IPv4
    if maclen is None:
        maclen = 6
    if plen is None:
        plen = 4
    if opcode is None:
        opcode = 1
    if ipsrc is None:
        ipsrc = get_default_interface_ip_linux()
    if ipdst is None:
        ipdst = get_default_gateway_ipv4_linux()

    return ArpLayer(hwtype=hwtype, ptype=ptype, maclen=maclen,plen=plen, opcode=opcode,
                    macsrc=macsrc, ipsrc=ipsrc, ipdst=ipdst, macdst=macdst)

def Dot3(dst: Union[str, bytes] = BROADCAST_MAC,
         src: Union[str, bytes] = None, length: int = 0) -> Dot3Layer:
    if src is None:
        src = get_default_interface_mac_linux()
    return Dot3Layer(dst=dst, src=src, length=length)

def VLAN(tpid=0x8100, priority=0, dei=0, vlan_id=1):
    return VLANLayer(tpid=tpid, priority=priority, dei=dei, vlan_id=vlan_id)

def LLC(dsap: Union[str, bytes] = None,ssap: Union[str, bytes] = None,
        control: Union[str, bytes] = LLC_UI):
    return LLCLayer(dsap=dsap, ssap=ssap, control=control)

def SNAP(oui: Union[str, bytes] = 0x000000,pid: Union[str, bytes] = None):
    return SNAPLayer(oui=oui, pid=pid)

def STP(protocol_version=0x00, bpdu_type=0x00, flags=0x00,
                 root_priority=0x8000, root_mac: Union[str,bytes] =b'\x00\x11\x22\x33\x44\x55',
                 root_path_cost=0, bridge_priority=0x8000,
                 bridge_mac : Union[str,bytes] =b'\x00\x11\x22\x33\x44\x55', port_id=0x8001,
                 message_age=0, max_age=5120, hello_time=512,
                 forward_delay=3840):

    return STPLayer(
            protocol_version=protocol_version,
            bpdu_type=bpdu_type,
            flags=flags,
            root_priority=root_priority,
            root_mac=root_mac,
            root_path_cost=root_path_cost,
            bridge_priority=bridge_priority,
            bridge_mac=bridge_mac,
            port_id=port_id,
            message_age=message_age,
            max_age=max_age,
            hello_time=hello_time,
            forward_delay=forward_delay
        )

def Raw(payload: bytes = b'Test LightPacket Raw Layer') -> RawLayer:
    return RawLayer(payload=payload)
