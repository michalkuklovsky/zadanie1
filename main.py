import socketserver
# import re
# import string
import socket
import socketserver
#import threading
import sys
import time
import logging

import sipfullproxy

HOST, PORT = '0.0.0.0', 5060

if __name__ == "__main__":    
    
    hostname = socket.gethostname()
    ipaddress = socket.gethostbyname(hostname)
    if ipaddress == "127.0.0.1":
        ipaddress = sys.argv[1]

    print("SIP Proxy - ip address:" + ipaddress)

    logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s',filename='calls.log',level=logging.INFO,datefmt='%H:%M:%S')
    logging.info("SIP Proxy started: " + time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    logging.info("SIP Proxy hostname: " + hostname)
    logging.info("SIP Proxy IP address: " + ipaddress + "\n")

    sipfullproxy.recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress,PORT)
    sipfullproxy.topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress,PORT)
    server = socketserver.UDPServer((HOST, PORT), sipfullproxy.UDPHandler)
    server.serve_forever()
    