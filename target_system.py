"""
DDOS Target System

Author: Meng-Ku Chen
Date: 2023-05-08
Description: The purpose of this application is to simulate the behavior of a target system during a DDOS (Distributed Denial of Service) attack. 
It provides a platform to test and analyze the impact of various types of attacks on the target system.
"""
from scapy.all import *
from threading import Thread
from flask import Flask, jsonify
import psutil

app = Flask(__name__)
# represents the homepage of the application and return a simple welcome message
@app.route('/')
def hello():
    return "I LOVE COSI-107A"
#represent the load of the system, returns the one minute average system load
@app.route('/load')
def get_load():
    load_avg_1m, _, _ = psutil.getloadavg()
    return jsonify({'load_avg_1m': load_avg_1m})
#represents a complex route which has heavy CPU computations
@app.route('/sort')
def sort_numbers():
    numbers = [random.randint(1, 1000) for _ in range(10000)]
    sorted_numbers = sorted(numbers)
    return 'Sorted {} numbers'.format(len(sorted_numbers))

if __name__ == '__main__':
    # HashMap to store packet frequency queues
    packet_frequency = defaultdict(lambda: deque(maxlen=10))
    time_window = 60
    # Replace this with your actual private IP address
    private_ip_address = "172.20.10.3"

    def packet_handler(packet):
        # Only process UDP packets that are sent to the target server
        if UDP in packet and packet.haslayer(IP) and packet.haslayer(IP) and packet[IP].dst == private_ip_address and packet[UDP].dport == 8080:
            # Extract the source IP address, source port number and payload from the packet
            src_ip = packet[IP].src
            src_port = packet[UDP].sport
            payload_data = packet[Raw].load
            packet_frequency[src_ip].append(time.time())
            #If the frequency of a source IP address exceeded the threshold, we considered the packet was suspicious and drop the packet.
            if len(packet_frequency[src_ip]) == packet_frequency[src_ip].maxlen and \
                packet_frequency[src_ip][-1] - packet_frequency[src_ip][0] < time_window:
                print(f"Suspicious packet frequency from {src_ip} within {time_window} seconds")
                return
            else:
                # Modify the payload data 
                modified_payload = payload_data.upper() 

                # Prepare the response packet with the modified payload
                send(IP(dst=src_ip)/UDP(dport=src_port)/Raw(load=modified_payload))
                print("sending back the packet with modified payload")
        # Only process TCP packets that are sent to the target server
        elif packet.haslayer(TCP) and packet.haslayer(IP) and packet[IP].dst == private_ip_address and packet[TCP].dport == 8080:
            # Extract the source IP address and source port number from the packet
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            packet_frequency[src_ip].append(time.time())
        # Check if the packet frequency exceeds the threshold within the time window, we considered the packet was suspicious and drop the packet.
            if len(packet_frequency[src_ip]) == packet_frequency[src_ip].maxlen and \
                packet_frequency[src_ip][-1] - packet_frequency[src_ip][0] < time_window:
                print(f"Suspicious packet frequency from {src_ip} within {time_window} seconds")
                return
            else:
                # Send back a SYN-ACK packet to establish the TCP connection
                send(IP(dst=src_ip)/TCP(dport=src_port, flags="SA"), verbose=False)
                print("make TCP connection")
            
        # Only process ICMP packets that are sent to the target server
        elif  ICMP in packet and packet.haslayer(IP) and packet[IP].dst == private_ip_address:
            # Extract the source IP address from the packet
            src_ip = packet[IP].src
            packet_frequency[src_ip].append(time.time())
            if len(packet_frequency[src_ip]) == packet_frequency[src_ip].maxlen and \
                packet_frequency[src_ip][-1] - packet_frequency[src_ip][0] < time_window:
                print(f"Suspicious packet frequency from {src_ip} within {time_window} seconds")
                return
            else:
                # Sent back an echo reply packet
                send(IP(dst=src_ip)/ICMP(type="echo-reply", id=packet[ICMP].id, seq=packet[ICMP].seq))
                print("Sent back an echo reply packet")


    def start_sniffing():
        # Start sniffing incoming traffic on the target server's network interface
        sniff(filter="udp or tcp or icmp", prn=packet_handler)

    # Start sniffing incoming traffic in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()

    # Runng the applcation on private IP address with port 8080 and wait for the sniffing and mitigation threads to complete
    app.run(host='172.20.10.3', port=8080)
    sniff_thread.join()


