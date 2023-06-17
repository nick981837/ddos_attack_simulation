"""
DDOS Attack Simulation
Website Response Time Measurement
Author: Meng-Ku Chen
Date: 2023-05-08
Description: This script measures the response time of a website by sending HTTP GET requests to a specified URL and port number. 
It is used to assess the performance of a server under continuous request load.
"""
import time
import requests
# Replace this with your actual private IP address and port number
host = '172.20.10.3'
port = 8080
path = '/sort'
# Continuously send requests and measure response time
while True:
    start_time = time.time()
    response = requests.get(f'http://{host}:{port}{path}')
    end_time = time.time()
    # Calculate and print the response time
    print(f'Time taken to receive the response: {end_time - start_time} seconds')