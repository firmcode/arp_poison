import socket
import subprocess, shlex
from scapy.all import *
import sys
from uuid import getnode as get_mac

#Myip
Mymac = "00:0c:29:6d:72:30"
Receiverip = "192.168.232.130"
#Receivermac
#Senderip
#sendermac
testmac = "aa:aa:aa:aa:aa:aa"
raw_packet_cache = None

def pkt_callback(pkt):
	#print pkt[0][1].src # debug statement
	#print pkt[0][1].dst	
	if pkt[IP].proto == "tcp":
		return ;
	if pkt.src==Mymac: 
		pkt[Ether].src=testmac
		pkt.display()
#		print str(pkt).encode("HEX")
#		del(pkt[IP].len)
#		del(pkt[UDP].len)
#		del(pkt[UDP].chksum)
		pkt.options.append(IPOption_MTU_Reply())
		send(pkt)	


DefFilter = "host "+Receiverip
sniff(prn=pkt_callback, filter="ip", store=0)

