#!/usr/bin/python3

from scapy.all import *
import sys
from time import sleep
import os
import socket

def parse_debug(port_arrived_times):

  def handle_pkt(pkt):

    try:

      if(pkt[Ether].src != "db:db:db:db:db:db"):
        return

      debug_data = pkt[Ether].load

      print("[*] New debug message")


      # Comment this out if debugging the LFA detection
      # start

      ip = socket.inet_ntoa(debug_data[0, 5])
      print(ip)

      return

      # end

      offset = 0
      for p in port_arrived_times:
        first_arrived = int.from_bytes(debug_data[offset:offset+4], "big")
        last_arrived = int.from_bytes(debug_data[offset+4:offset+8], "big")
        count = int.from_bytes(debug_data[offset+8:offset+12], "big")

        p["first_arrived"] = first_arrived
        if(count == 0):
          p["last_arrived"] = []
          p["count"] = 0

        elif(count > p["count"]):
          p["last_arrived"].append(last_arrived)
          p["count"] = count

        offset+=12

      print(port_arrived_times)

    except TypeError: #Exception as e:
      print("Unable to get debug data")
      print(e)

  return handle_pkt

def main():

    port_arrived_times = []

    port_arrived_times.append({"first_arrived": 0, "last_arrived": [], "count": 0}) # CPU port
    port_arrived_times.append({"first_arrived": 0, "last_arrived": [], "count": 0}) # Port 1
    port_arrived_times.append({"first_arrived": 0, "last_arrived": [], "count": 0}) # Port 2
    port_arrived_times.append({"first_arrived": 0, "last_arrived": [], "count": 0}) # Port 3

    try:
      iface = sys.argv[1]
    except:
        print("python3 parse_debug.py <iface>")
        exit()

    print("Starting script to send debug messages...")
    os.system("python3 get_debug.py " + iface + " &")

    print("Starting sniff on iface...")
    sniff(iface=iface, filter="ether proto 0xdbdb", prn=parse_debug(port_arrived_times))

main()