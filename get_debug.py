#!/usr/bin/python3

from scapy.all import *
from time import sleep
import os

def main():
  iface = sys.argv[1]
  send_count = 3250
  delay = 1

  payload = (b'\xdb'*48)
  for i in range(0, send_count):
    sendp(Ether(dst="DE:AD:DE:AD:DE:AD", src=get_if_hwaddr(iface), type=0xdbdb)/payload, iface=iface)
    sleep(delay)

main()