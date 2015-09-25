#! /usr/bin/perl -w
#
# Copyright (C) 2015 by Thomas Hemmingby Espe <thomas.espe@gmail.com>
#

use warnings;
use strict;

use Getopt::Std;
use Net::MAC;

$Getopt::Std::STANDARD_HELP_VERSION = 1;
$main::VERSION = '0.01';

# options processing
my %opts;
getopts('d', \%opts);


# create MAC object
my $mac = Net::MAC->new('mac' => $ARGV[0]);

if ($opts{'d'}) {
    # print mac in format suitable for dhcpd hardware ethernet declarations
    print $mac->convert('delimiter' => ':') ."\n";
}


sub HELP_MESSAGE () {
    print <<EOF
Usage: wfmac.pl [-d] MAC

Checks MAC validity and optionally print in a specified format.
Without any options, the script only checks the validity of the MAC,
as Net::MAC->new dies with a value of 255 if the MAC is invalid.

Options:
 -d:
   Print the MAC address as expected by ISC dhcpd in hardware ethernet declaration
EOF
}


#print $mac;
exit 0;

