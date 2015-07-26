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
    """
    Main function
    
    :return: Exit value of program
    :rtype: int
    """

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
    return 0


def display(lst, full):
    """
    Display the result on screen

    :param lst: A list of namedtuples
    :type lst: list
    :param full: display full information or not
    :type full: bool
    """
    if full:
        for h in lst:
            print "%s (%s): %s" % (h.name, h.ip, h.os)
    else:
        for h in lst:
            print "%s: %s" % (h.name, h.os)


def scan_range(subnet):
    """
    Scan the subnet provided for OS fingerprints
    
    :param subnet: a subnet object
    :type subnet: netaddr.IPNetwork
    :return: A list of active hosts
    :rtype: list
    """
    reslist = []

    nm = make_scanner()
    for sb in subnet:
        for ip in sb.iter_hosts():
            ipstr = str(ip)
            try:
                nm.scan(ipstr, arguments='-O')
            except NM.PortScannerError as scanerr:
                sys.stderr.write(
                    "Caught PortScannerError on ip {}: \n".format(ipstr))
                sys.stderr.write("{}\n".format(scanerr.message))
                continue
            
            if not check_status(nm):
                continue

            hostnam = lookuphost(ipstr)

            reslist.append(make_res_host(nm, hostnam, ipstr))

    return reslist


def scan_ip(ipaddr):
    """
    Scans a list of IPs for OS fingerprints

    :param ipaddr: A list of IP addresses to scan
    :type ipaddr: list
    :return: A list with namedtuples of type Host
    :rtype: list
    """
    reslist = []

    nm = make_scanner()

    for ip in ipaddr:
        osclass = ''

        ipstr = str(ip)

        try:
            nm.scan(ipstr, arguments='-O')
        except NM.PortScannerError as scanerr:
            sys.stderr.write(dedent('''
            Caught PortScannerError on ip {}:
            {}
            ''').format(ipstr, scanerr.message))

        if not check_status(nm):
            continue

        hostnam = lookuphost(ipstr)

        reslist.append(make_res_host(nm, hostnam, ipstr))
    return reslist


def make_scanner():
    """
    Create a nmap.PortScanner object

    :return: nmap.PortScanner object
    :rtype: nmap.PortScanner
    :raises: nmap.PortScannerError
    """
    try:
        nm = NM.PortScanner()
    except NM.PortScannerError as nmaperr:
        print dedent('''
        Error initializing portscanner object: {}
        Is nmap installed?
        ''').format(str(nmaperr)).strip()
        raise
    return nm


def check_status(nm):
    """
    Check status of nmap scan

    :param nm: nmap scan object
    :type nm: nmap.PortScanner
    :return: True if scan was ok, False otherwise
    :rtype: bool
    """
    if nm.all_hosts():
        return True
    else:
        return False


def lookuphost(ip):
    """
    Look up hostname from ip. Returns hostname if found, ip otherwise

    :param ip: The IP to look up
    :type ip: str.
    :return: hostname or ip
    :rtype: str.
    """
    try:
        hostnam = socket.gethostbyaddr(ip)[0]
    except socket.herror as herr:
        sys.stderr.write("Unable to look up {}: \n".format(ip))
        sys.stderr.write("{}\n".format(herr.message))
        hostnam = ip
    return hostnam


def make_res_host(nm, hnam, ip):
    """
    Extract information from nmap object and create Host tuple

    :param nm: nmap portscanner object
    :type nm: nmap.PortScanner
    :param hnam: hostname
    :type hnam: str
    :param ip: IP address
    :type ip: str
    :return: nametuple of type Host
    :rtype: namedtuple
    """
    osclass = ''
    try:
        state = nm[ip]['status']['state']
        try:
            osclass = nm[ip]['osclass'][0]['osfamily']
        except KeyError as __:
            osclass = 'unknown'
    except KeyError as __:
        state = 'unknown'
    return Host(hnam, ip, state, osclass)


def parse_ip_range(iprange):
    """
    Parse a list of ipranges into subnets
    
    :param iprange: The IP range to parse
    :type iprange: list
    :return: An list representing subnets 
    :rtype: list
    """
    subnetlist = []

    for sb in iprange:
        try:
            subnet = NA.IPNetwork(sb)
        except NA.AddrFormatError as err:
            print "Caught exception: " % err.message
            continue
        subnetlist.append(subnet)
    return subnetlist


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
    """
    Parse options and return the resulting object
    """
    parser = argparse.ArgumentParser(description='Find OS of hosts in subnet')
    parser.add_argument('-s', help="String to search for in resulting OS scan",
                        action="store", dest='search')
    parser.add_argument('-F',
                        help="Full listing of result, otherwise hostname and OS is displayed",
                        action="store_true", default=False, dest='full')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', help="IP address",
                       action="store", nargs='+', dest='ip', default=[])
    group.add_argument('-r', help="IP range (subnet)", action="store",
                       nargs='+', dest='iprange', default=[])

    return parser.parse_args()


if (__name__ == "__main__"):
    sys.exit(main())
