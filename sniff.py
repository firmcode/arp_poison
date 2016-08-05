import socket
import subprocess, shlex
from scapy.all import *
import sys
from uuid import getnode as get_mac

#Myip= "192.168.218.174"
#Mymac = "00:0c:29:d7:80:2d"
#Senderip = "192.168.218.151"
#Sendermac = "00:0C:29:10:23:d3"
#Receiverip = "192.168.218.2"
#Receivermac = "00:50:56:ff:4b:b4"

Myip =""
Mymac=""
Senderip=""
Seddermac=""
Receiverip=""
Receivermac=""


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
                        print "send"
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
                        print "send"
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
                        print "send"

			sendp(pkt)
			#print "send!!!"	

		if pkt[IP].src==Receiverip: 
                        pkt[Ether].src=Mymac
			pkt[Ether].dst=Sendermac

                        del pkt.len
                        #del pkt[TCP].chksum
                        del pkt.chksum
                        pkt = pkt.__class__(str(pkt))
                        print "send"

                        sendp(pkt)


#Get MY Address!!!!!!!!!!!!
strs = subprocess.check_output(shlex.split('ip r l'))
Myip  = strs.split('src')[-1].split()[0]
Mymac = get_mac()
Mymac =':'.join(("%012X" % Mymac)[i:i+2] for i in range(0, 12, 2))
Mymac= Mymac.lower()
print "Myip :"+ Myip+"  Mymac :"+Mymac


#Get Receiver Address!!!!!!!!!!!
Receiverip = strs.split('default via')[-1].split()[0]
send(ARP(op=1, pdst=Receiverip, psrc=Myip, hwdst="ff:ff:ff:ff:ff:ff"))
result, unanswered = sr(ARP(op=ARP.who_has, pdst=Receiverip))
Receivermac = result[0][1].hwsrc
print "Receiverip : "+Receiverip+" Receivermac : "+Receivermac

#Get Sender Address!!!!!!!!!!!
Senderip=raw_input("Enter SenderIP : ")
print Senderip
send(ARP(op=1, pdst=Senderip, psrc=Myip, hwdst="ff:ff:ff:ff:ff:ff"))
result, unanswered = sr(ARP(op=ARP.who_has, pdst=Senderip))
Sendermac=result[0][1].hwsrc
print "Senderip : "+Senderip+" Sendermac : "+Sendermac



DefFilter = "host "+Receiverip+" or host "+Senderip
print "hello"
sniff(prn=pkt_callback, lfilter=lambda d: d.dst == Mymac, store=1)
