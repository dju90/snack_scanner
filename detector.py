import dpkt
from dpkt.ip import IP
from dpkt.icmp import ICMP
import socket
import sys

# aliases
ETH = dpkt.ethernet.Ethernet
ACK = dpkt.tcp.TH_ACK
SYN = dpkt.tcp.TH_SYN

def run():
	f = open(sys.argv[1])
	pcap = dpkt.pcap.Reader(f)

	packets = []
	syn_ct = {}
	syn_ack_ct = {}
	i = 0
	for ts, buf in pcap:
		if i % 100000 == 0:
			print "Analyzing packet number " + str(i)
		i += 1
		try:
			eth = ETH(buf)
			if eth.type!=dpkt.ethernet.ETH_TYPE_IP and eth.type!=dpkt.ethernet.ETH_TYPE_IP6:
				continue         
			ip=eth.data
			if ip.p!=dpkt.ip.IP_PROTO_TCP:
				continue
			tcp=ip.data
			
			if SYN:
				if not ACK:
					print "syn"
					# dec = str(ip.src).strip().split("\x")
					# print dec
					# ip_addr = ""
					# for d in dec:
					# 	ip_addr += str(int("0x"+str(d)))
					ip_addr = str(ip.src)
					ip_addr = socket.inet_ntoa(ip_addr)
					if ip_addr not in syn_ct.keys():
						syn_ct[ip_addr] = 0
					syn_ct[ip_addr] += 1
				else:
					ip_addr = str(ip.dst)
					ip_addr = socket.inet_ntoa(ip_addr)
					if ip_addr not in syn_ack_ct.keys():
						syn_ack_ct[ip_addr] = 0
					syn_ack_ct[ip_addr] += 1				
		except dpkt.UnpackError:
			pass

	print syn_ct
	# print syn_ack_ct
	for ip in syn_ct:
		# if ip in syn_ack_ct and syn_ct[ip] > (syn_ack_ct[ip]):
		print str(ip) + ": " + str(syn_ct[ip]) + ", " + str(syn_ack_ct[ip])

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print "Usage: python compare.py PCAP_FILE.pcap"
    sys.exit(0)
  else:
    run()