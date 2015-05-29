#!/usr/bin/python
#
##
# Copyright (C) 2014 by Thomas Hemmingby Espe <te@nilu.no>
#

"""
Scan a subnet for host and try to ascertain the OS
of a particular host
"""

import sys
import argparse
import netaddr as NA
import nmap as NM
import socket
import re
import os
from collections import namedtuple
from textwrap import dedent

Host = namedtuple('Host', 'name ip state os')

def main ():
    """Main function"""

    if (os.geteuid() != 0):
        print dedent('''
        This program performs OS finger printing via NMAP.
        To do this, root privileges (or sudo) are required.
        ''').strip()
        return 77 # EX_NOPERM

    opts = parse_args()
    ipn = None

    if not opts.iprange or opts.ip:
        print "Iprange must be provided"
        return 1
        
    if opts.iprange:
        ipn = parse_ip_range(opts.iprange)
        if not ipn:
            return 1
    else:
        # single ip adresses are not implemented (yet)
        return 1
    
    result = scan(ipn)
    if opts.search:
        mask = re.compile(opts.search, re.I)
        display( [ lst for lst in result if mask.search(lst.os) ],
                 opts.full)
    else:
        display(result, opts.full)
        
def display(lst, full):
    """Display the result on screen"""
    if full:
        for h in lst:
            print "%s (%s): %s" % (h.name, h.ip, h.os)
    else:
        for h in lst:
            print "%s: %s" % (h.name, h.os)
                

def scan(subnet):
    """Scan the subnet provided for OS fingerprints"""
    reslist = []
    
    try:
        nm = NM.PortScanner()
    except NM.PortScannerError as nmaperr:
        print dedent('''
        Error initializing portscanner object: {}
        Is nmap installed?
        ''').format(str(nmaperr)).strip()
        sys.exit(69) # nmap (possibly) unavailable

    for ip in subnet.iter_hosts():
        ipstr = str(ip)
        try:
            nm.scan(ipstr, arguments='-O')
        except NM.PortScannerError as scanerr:
            sys.stderr.write("Caught PortScannerError on ip {}\n".format(ipstr))
            continue
            
        if nm[ipstr]['status']['state'] != 'up':
            continue
            #if nm[ipstr].hostname() == '':
        try:
            hostnam = socket.gethostbyaddr(ipstr)[0]
        except socket.herror as herr:
            sys.stderr.write("Unable to look up {}\n".format(ipstr))
            hostnam = ipstr
            # hostnam = nm[ipstr].hostname()
        # else:
        #     hostnam = ipstr
        try:
            reslist.append(Host(hostnam,
                                ipstr,
                                nm[ipstr]['status']['state'],
                                nm[ipstr]['osclass'][0]['osfamily']))
        except KeyError as kerr:
            reslist.append(Host(hostnam,
                                ipstr,
                                nm[ipstr]['status']['state'],
                                'unknown'))
    return reslist

def parse_ip_range(iprange):
    """Parse an iprange into a subnet"""
    subnet = None
    try:
        subnet = NA.IPNetwork(iprange)
    except NA.AddrFormatError as err:
        print "Caught exception" % err.message
        return None
    return subnet
    
def parse_args():
    """Parse options and return the resulting object"""
    parser = argparse.ArgumentParser(description='Find OS of hosts in subnet')
    parser.add_argument('-s', help="String to search for in resulting OS scan", action="store", dest='search')
    parser.add_argument('-F', help="Full listing of result, otherwise hostname and OS is displayed",
                        action="store_true", default=False, dest='full')
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', help="IP adress (not implemented yet)", action="store", dest='ip')
    group.add_argument('-r', help="IP adress or range", action="store", dest='iprange')

    return parser.parse_args()



if (__name__ == "__main__"):
    sys.exit(main())
