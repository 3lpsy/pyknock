#!/usr/bin/env python3
import logging
import sys
import time
import argparse
from scapy.all import send, IP, TCP
from libnmap.process import NmapProcess
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import itertools

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def parse_ports(content):
    print('[*] parsing nmap output...')
    map = NmapParser.parse(content)
    return map.hosts[0].get_ports()

def scan_ports(ip, ports="0-65535"):
    nm = NmapProcess(ip, options="-p {}".format(ports))
    time.sleep(5)
    rc = nm.run()
    if nm.rc == 0:
        return parse_ports(nm.stdout)
    else:
        print(nm.stderr)
        sys.exit()

def collect_open_ports(ip, ports, nmap_file=None):
    if not nmap_file:
        print('[*] running nmap on ip', ip, 'looking for', ports)
        return scan_ports(ip, ports)
    else:
        print('[*] opening nmap file')
        with open(nmap_file) as f:
            content = f.read()
            return parse_ports(content)

def knock(ip, ports, sleep=1):
    print("[*] starting knock sequency", ports)
    for port in ports:
        print("[*] knocking on {}:{}".format(ip, port))
        send(IP(dst=ip)/TCP(dport=int(port)), verbose=0)

def knockit(ip, key, ports="0-65535", nmap_file=None, confirm=True):
    open_ports = collect_open_ports(ip, ports, nmap_file)

    if len(open_ports) > 0:
        print('[*] all currently open ports...')
        for x in open_ports:
            print("[+]", str(x), "is open")
    else:
        print("[*] no ports currently open")

    knock(ip, key)
    if confirm:
        opened_ports = collect_open_ports(ip, ports)

        newly_opened = list(set(opened_ports) - set(open_ports))

        if len(newly_opened) > 0:
            print("[**]" + str(len(newly_opened)) + " new port(s) opened...")
            for x in newly_opened:
                print("[+++]", str(x), "has opened")
        else:
            print("[!] no newly opened ")
            print("[!] last found ports ({})".format(len(opened_ports)))
            for x in opened_ports:
                print("[+]", str(x), "is open")
    else:
        print("[!] skipping confirmation")
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ip', type=str, required=True, help="ip")
    parser.add_argument('-k', '--key', action="append", default=[], help="target ports to check(nmap format)")
    parser.add_argument('-p', '--ports', type=str, default="0-65535", help="ports (nmap format)")
    parser.add_argument('-n', '--nmap', type=str, help="/path/to/output.xml")
    parser.add_argument('-c', '--check', action="store_true", help="just check ports status")
    parser.add_argument('-m', '--mutate', action="store_true", help="just check ports status")
    parser.add_argument('-C', '--no-confirm', action="store_true", help="just check ports status", default=False)
    args = parser.parse_args()
    confirm = not args.no_confirm
    if args.check:
        print('[*] knockit: just checking for ports (not knocking)')
        open_ports = collect_open_ports(args.ip, args.ports)
        if len(open_ports) > 0:
            print('[*] all currently open ports...')
            for x in open_ports:
                print("[+]", str(x), "is open")
        else:
            print("[*] no ports currently open")
    else:
        key = args.key
        ip = args.ip

        if not args.key:
            print("[!] please pass in a port key (like [6000, 7000, 8000])")

        print('[*] knockit...')
        print('[*] ip: ', ip)
        print('[*] key: ', key)
        print('[*] suspect ports: ', args.ports)
        if args.nmap:
            print('[*] nmap file: ', args.nmap)
        if args.mutate:
            print('[*] mutate: ', args.mutate)
        if not args.mutate:
            knockit(ip, key, args.ports, args.nmap, confirm=confirm)
        else:
            keysets = list(itertools.permutations(args.key))
            for key in keysets:
                print('[*] mutatation: ', str(key))
                knockit(ip, key, args.ports, args.nmap, confirm=confirm)
