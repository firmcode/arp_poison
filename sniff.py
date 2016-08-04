import socket
import subprocess, shlex
from scapy.all import *
import sys
from uuid import getnode as get_mac

#Myip
Mymac = "00:0c:29:d7:80:2d"
Receiverip = "192.168.232.130"
#Receivermac
#Senderip
#sendermac
testmac = "00:50:56:aa:aa:aa"
testmac1 = "00:50:56:bb:bb:bb"

raw_packet_cache = None

def pkt_callback(pkt):
	
	#print pkt[0][1].src # debug statement
	#print pkt[0][1].dst	
	if pkt[IP].proto == "udp":
		return 
	if pkt[0].haslayer(TCP):
		if pkt.src==Mymac: 
			pkt[Ether].src=testmac
                        pkt[Ether].dst=testmac1

	#		print str(pkt).encode("HEX")
	#		del(pkt[IP].len)
	#		del(pkt[UDP].len)
	#		del(pkt[UDP].chksum)		
	#		pkt.options.append(IPOption_MTU_Reply())
			del pkt[IP].len
			del pkt[TCP].chksum
	               	del pkt[IP].chksum
			#print pkt.show2()
			pkt = pkt.__class__(str(pkt))
			pkt.display()
			sendp(pkt)
			print "send!!!"	


DefFilter = "host "+Receiverip
print "hello"
sniff(prn=pkt_callback, filter="ip", store=0)
