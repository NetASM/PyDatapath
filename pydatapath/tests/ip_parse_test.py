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

# ###############################################################################
# Packet parsing policies
# ###############################################################################


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


# IP packet (requires eth_type to be already extracted)
def parse_ip(offset=112):
    return (extract(ip_ver=(offset, 0, 4),
                    ip_ihl=(offset, 4, 4),
                    ip_dscp=(offset, 8, 6),
                    ip_ecn=(offset, 14, 2),
                    ip_tlen=(offset, 16, 16),
                    ip_id=(offset, 32, 16),
                    ip_flgs=(offset, 48, 3),
                    ip_fo=(offset, 51, 13),
                    ip_ttl=(offset, 64, 8),
                    ip_prtcl=(offset, 72, 8),
                    ip_chksm=(offset, 80, 16),
                    ip_srcip=(offset, 96, 32),
                    ip_dstip=(offset, 128, 32)) >> modify(has_ip=1) >>

            modify(ip_ihl_bits=op_.mul('ip_ihl', 32)) >>

            if_(match(ip_ihl=cmp_.gt(5)),
                modify(ip_op_len=op_.sub('ip_ihl_bits', 160)) >>
                extract(ip_op=(offset, 160, 'ip_op_len')) >> modify(has_ip_op=1),
                passthrough))


# Packet payload
def parse_payload(offset):
    return extract(payload=(offset, 0, EOP))


# Parse packet ######
def parse_ip_other_payload(offset=112):
    return if_(~match(eth_type=ETH_IPv4),
               parse_payload(offset),
               parse_ip(offset) >>
               modify(ip_ihl_bits=op_.mul('ip_ihl', 32)) >> modify(offset=op_.add(offset, 'ip_ihl_bits')) >>
               parse_payload('offset'))


parse_packet = parse_ethernet(0) >> \
               if_(match(eth_type=ETH_VLAN),
                   parse_ieee802_1q(112) >> parse_ip_other_payload(144),
                   parse_ip_other_payload(112))


# ###############################################################################
# Main policy
# ###############################################################################
def main():
    # An example of pre-packet processing (use-case: RMT, FlexPipe)
    test1 = parse_packet >> \
            ((match(eth_srcmac=0x000000000001) >> modify(outport=2)) +
             (match(eth_srcmac=0x000000000002) >> modify(outport=1)))

    # An example of on-demand packet processing (use-case: NPUs, SW, FPGAs)
    # Note: first, we parse only the Ethernet packet and then perform a match+action,
    # then we further parse the packet to extract IP protocol to drop all TCP traffic.
    # In this case ping will work but iperf (using TCP) won't.
    test2 = parse_ethernet(0) >> \
            ((match(eth_srcmac=0x000000000001) >> modify(outport=2)) +
             (match(eth_srcmac=0x000000000002) >> modify(outport=1))) >> \
            parse_ip_other_payload(112) >> \
            (~match(ip_prtcl=IP_PRTCL_TCP))

    return test1
