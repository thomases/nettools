#!/usr/bin/python
#
##
# Copyright (C) 2014, 2015 by Thomas Hemmingby Espe <te@nilu.no>
#

"""
Scan a subnet for host and try to ascertain the OS
of a particular host or hosts
"""

import sys
import argparse
import netaddr as NA
import nmap as NM
import socket
import re
import os
import posix
from collections import namedtuple
from textwrap import dedent

Host = namedtuple('Host', 'name ip state os')


def main():
    """Main function"""
    
    opts = parse_args()

    if (os.geteuid() != 0):
        print dedent('''
        This program performs OS finger printing via NMAP.
        To do this, root privileges (or sudo) are required.
        ''').strip()
        return posix.EX_NOPERM

    ipn = None
    ip = None
    result = None

    if opts.iprange:
        ipn = parse_ip_range(opts.iprange)
        result = scan_range(ipn)
    else:
        ip = parse_ip(opts.ip)
        result = scan_ip(ip)

    if opts.search:
        mask = re.compile(opts.search, re.I)
        display([lst for lst in result if mask.search(lst.os)],
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


def scan_range(subnet):
    """Scan the subnet provided for OS fingerprints"""
    reslist = []

    try:
        nm = NM.PortScanner()
    except NM.PortScannerError as nmaperr:
        print dedent('''
        Error initializing portscanner object: {}
        Is nmap installed?
        ''').format(str(nmaperr)).strip()
        sys.exit(posix.EX_UNAVAILABLE)  # nmap (possibly) unavailable

    for ip in subnet.iter_hosts():
        ipstr = str(ip)
        try:
            nm.scan(ipstr, arguments='-O')
        except NM.PortScannerError as scanerr:
            sys.stderr.write("Caught PortScannerError on ip {}: \n".format(ipstr))
            sys.stderr.write("{}\n".format(scanerr.msg))
            continue

        if not nm.all_hosts():
            continue
        
        try:
            hostnam = socket.gethostbyaddr(ipstr)[0]
        except socket.herror as herr:
            sys.stderr.write("Unable to look up {}: \n".format(ipstr))
            sys.stderr.write("{}\n".format(herr.message))
            hostnam = ipstr


        try:
            state = nm[ipstr]['status']['state']
            osclass = nm[ipstr]['osclass'][0]['osfamily']
            reslist.append(Host(hostnam,
                                ipstr,
                                state,
                                osclass))
        except KeyError as __:
            reslist.append(Host(hostnam,
                                ipstr,
                                'unknown',
                                'unknown'))
    return reslist


def scan_ip(ipaddr):
    """
    Scans a list of single IPs

    :param ipaddr: A list of IP addresses to scan
    :type ipaddr: list
    :return: A list with namedtuples of type Host
    :rtype: list
    """
    reslist = []
    for ip in ipaddr:
        nm = None
        osclass = ''
        try:
            nm = NM.PortScanner()
        except NM.PortScannerError as nmaperr:
            print dedent('''
            Error initializing portscanner object: {}
            Is nmap installed?
            ''').format(str(nmaperr)).strip()
            sys.exit(posix.EX_UNAVAILABLE)  # nmap (possibly) unavailable

        ipstr = str(ip)

        try:
            nm.scan(ipstr, arguments='-O')
        except NM.PortScannerError as scanerr:
            sys.stderr.write(dedent('''
            Caught PortScannerError on ip {}:
            {}
            ''').format(ipstr, scanerr.msg))
            
        if not nm.all_hosts():
            continue

        try:
            hostnam = socket.gethostbyaddr(ipstr)[0]
        except socket.herror as herr:
            sys.stderr.write("Unable to look up {}: \n".format(ipstr))
            sys.stderr.write("{}\n".format(herr.message))
            hostnam = ipstr

        try:
            state = nm[ipstr]['status']['state']
            try:
                osclass = nm[ipstr]['osclass'][0]['osfamily']
            except KeyError as __:
                osclass = 'unknown'
        except KeyError as __:
            state = 'unknown'


        reslist.append(Host(hostnam,
                            ipstr,
                            state,
                            osclass))
    return reslist


def parse_ip_range(iprange):
    """Parse an iprange into a subnet"""
    subnet = None
    try:
        subnet = NA.IPNetwork(iprange)
    except NA.AddrFormatError as err:
        print "Caught exception: " % err.message
        return None
    return subnet


def parse_ip(ip):
    """
    Parse a list of IPs into netaddr.IPAddress objects

    :param str ip: A string of IPs, separated by commas
    :raises: netaddr.AddrFormatError on malformed IPs
    :return: A list of netaddr.IPAddress objects
    :rtype: list
    """
    iplist = []
    for ipt in ip:
        try:
            if NA.valid_ipv4(ipt) or NA.valid_ipv6(ipt):
                iplist.append(NA.IPAddress(ipt))
            else:
                raise NA.AddrFormatError
        except NA.AddrFormatError as err:
            print "Caught exception: {}".format(err.message)
            raise
    return iplist


def parse_args():
    """Parse options and return the resulting object"""
    parser = argparse.ArgumentParser(description='Find OS of hosts in subnet')
    parser.add_argument('-s', help="String to search for in resulting OS scan",
                        action="store", dest='search')
    parser.add_argument('-F', help="Full listing of result, otherwise hostname and OS is displayed",
                        action="store_true", default=False, dest='full')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', help="IP adress (not implemented yet)", 
                       action="store", nargs='+', dest='ip', default=[])
    group.add_argument('-r', help="IP adress or range", action="store",
                       dest='iprange')

    return parser.parse_args()


if (__name__ == "__main__"):
    sys.exit(main())
