import time



# --- scapy ---
from LightPacket import PcapRead
t0 = time.perf_counter()
n = 0
PcapRead("11111.pcap")

t1 = time.perf_counter()
print(f"lightpacket: {n} pkts in {t1-t0:.3f}s  ->  {n/(t1-t0):,.0f} pkt/s")