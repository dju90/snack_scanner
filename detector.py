import dpkt
from dpkt.ip import IP
from dpkt.icmp import ICMP
import socket
import sys

# aliases
ETH = dpkt.ethernet.Ethernet
IP  = dpkt.ethernet.ETH_TYPE_IP
IP6 = dpkt.ethernet.ETH_TYPE_IP6
ACK = dpkt.tcp.TH_ACK
SYN = dpkt.tcp.TH_SYN

def run():
	file = open(sys.argv[1])
	pcap = dpkt.pcap.Reader(file)

	syn_ct = {}
	syn_ack_ct = {}
	i = 0
	for ts, buf in pcap:
		if i % 100000 == 0:
			print "Analyzing packet number " + str(i)
		i += 1
		try:
			eth = ETH(buf)
			if eth.type!=IP and eth.type!=IP6:
				continue         
			ip=eth.data
			if ip.p!=dpkt.ip.IP_PROTO_TCP:
				continue
			tcp=ip.data
			# fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
			syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
			# rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
			# psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
			ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
			# urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
			# ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
			# cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0

			if syn_flag:
				if not ack_flag:
					incr_dict(ip.src, syn_ct)
				else:
					incr_dict(ip.dst, syn_ack_ct)				
		except dpkt.UnpackError:
			pass

	print syn_ct
	print syn_ack_ct
	for ip in syn_ct:
		if ip in syn_ack_ct and syn_ct[ip] > (syn_ack_ct[ip] * 3):
			print str(ip) + ": " + str(syn_ct[ip]) + ", " + str(syn_ack_ct[ip])
		elif ip not in syn_ack_ct and syn_ct[ip] > 0:
			print str(ip) + ": " + str(syn_ct[ip]) + ", " + str(syn_ack_ct[ip])

def incr_dict(hex_addr, dict):
	ip_addr = socket.inet_ntoa(str(hex_addr))
	if ip_addr not in dict.keys():
		dict[ip_addr] = 0
	dict[ip_addr] += 1

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print "Usage: python compare.py PCAP_FILE.pcap"
    sys.exit(0)
  else:
    run()