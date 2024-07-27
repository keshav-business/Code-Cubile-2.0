from scapy.all import *
from scapy.layers import Dot11

interface = raw_input('Enter your Network Interface > ')

Packet_Counter = 1


def info(packet):
    if packet.haslayer(Dot11):
        # The packet.subtype==12 statement indicates the deauth frame
        if ((packet.type == 0) & (packet.subtype==12)):
            global Packet_Counter
            print ("[+] Deauthentication Packet detected ! ", Packet_Counter)
            Packet_Counter = Packet_Counter + 1

#Sniffing and Detecting
sniff(iface=interface,prn=info)
