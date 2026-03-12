from scapy.all import sniff
def analyze_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]

        print("Source IP:", ip_layer.src)
        print("Destination IP:", ip_layer.dst)
        print("Protocol:", ip_layer.proto)
        print("Packet Length:", len(packet))
        print("---------------------------")
print("Capturing packets...")
sniff(prn=analyze_packet, count=10)
