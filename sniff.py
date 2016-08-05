import socket
import subprocess, shlex
from scapy.all import *
import sys
from uuid import getnode as get_mac

Myip= "192.168.218.174"
Mymac = "00:0c:29:d7:80:2d"
Senderip = "192.168.218.151"
Sendermac = "00:0C:29:10:23:d3"
Receiverip = "192.168.218.2"
Receivermac = "00:50:56:ff:4b:b4"
testmac = "00:50:56:aa:aa:aa"
testmac1 = "00:50:56:bb:bb:bb"

raw_packet_cache = None

def pkt_callback(pkt):
	#pkt.display()
	#if not (((pkt[Ether].src==Sendermac)and(pkt[Ether].dst==Mymac))or((pkt[Ether].dst==Mymac)and(pkt[Ether].src==Receivermac))):
	#	return
	if pkt[Ether].dst!=Mymac:
		return
	if ARP in pkt:
		return

	if pkt[0].haslayer(UDP):
		if pkt[IP].src==Senderip:
                        pkt[Ether].src=Mymac
			pkt[Ether].dst=Receivermac
                        del pkt.len
			del pkt[UDP].chksum
                        del pkt[UDP].len
                        del pkt.chksum
                        pkt = pkt.__class__(str(pkt))
                        sendp(pkt)

		if pkt[IP].src==Receiverip : 
			pkt[Ether].src=Mymac
			pkt[Ether].dst=Sendermac
                        del pkt.len
                        del pkt[UDP].len
			del pkt[UDP].chksum
                        del pkt.chksum
                        pkt = pkt.__class__(str(pkt))
                        sendp(pkt)

	else :
		if pkt[IP].src==Senderip: 
		#	send(Ether(dst=testmac)/pkt)
                        pkt[Ether].src=Mymac
                        pkt[Ether].dst=Receivermac
			del pkt.len
			#del pkt[TCP].chksum
	               	del pkt.chksum
			#print pkt.show2()
			pkt = pkt.__class__(str(pkt))
			#ipkt.display()
			sendp(pkt)
			#print "send!!!"	

		if pkt[IP].src==Receiverip: 
                        pkt[Ether].src=Mymac
			pkt[Ether].dst=Sendermac

                        del pkt.len
                        #del pkt[TCP].chksum
                        del pkt.chksum
                        pkt = pkt.__class__(str(pkt))
                        sendp(pkt)


DefFilter = "host "+Receiverip+" or host "+Senderip
print "hello"
sniff(prn=pkt_callback, filter=DefFilter, store=1)
