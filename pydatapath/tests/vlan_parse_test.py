####################################################################################
##
##  https://github.com/NetASM/pydatapath
##
##  File:
##        pydatapath.py
##
##  Project:
##        Pydatapath: pyretic extensions for programmable datapaths
##
##  Author:
##        Muhammad Shahbaz
##
##  Copyright notice:
##        Copyright (C) 2014 Georgia Institute of Technology
##           Network Operations and Internet Security Lab
##
##  Licence:
##        This file is a part of the NetASM development base package.
##
##        This file is free code: you can redistribute it and/or modify it under
##        the terms of the GNU Lesser General Public License version 2.1 as
##        published by the Free Software Foundation.
##
##        This package is distributed in the hope that it will be useful, but
##        WITHOUT ANY WARRANTY; without even the implied warranty of
##        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##        Lesser General Public License for more details.
##
##        You should have received a copy of the GNU Lesser General Public
##        License along with the Pydatapath source package.  If not, see
##        http://www.gnu.org/licenses/.

__author__ = 'shahbaz'

from pydatapath.core import *


# Ethernet
def parse_ethernet(offset=0):
    return extract(eth_dstmac=(offset, 0, 48),
                   eth_srcmac=(offset, 48, 48),
                   eth_type=(offset, 96, 16))


# IEEE802_1Q (requires eth_type to be already extracted)
def parse_ieee802_1q(offset=112):
    return (extract(vlan_pcp=(offset, 0, 3),
                    vlan_cfi=(offset, 3, 1),
                    vlan_vid=(offset, 4, 12),
                    vlan_type=(offset, 16, 16)) >> modify(has_vlan=1))


# Packet payload
def parse_payload(offset):
    return extract(payload=(offset, 0, EOP))


# Parse packet
parse_packet = parse_ethernet(0) >> \
               if_(match(eth_type=ETH_VLAN),
                   parse_ieee802_1q(112) >> parse_payload(144),
                   parse_payload(112))


# ###############################################################################
# Main policy
# ###############################################################################

def main():
    policy = parse_packet >> \
             ((match(eth_srcmac=0x000000000001) >> modify(outport=2)) +
              (match(eth_srcmac=0x000000000002) >> modify(outport=1)))

    return policy