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
import pydatapath.core.policies.packet as packet

# ###############################################################################
# Packet parsing policies
# ###############################################################################


def parse_ip_other_payload(offset=112):
    return if_(~match(eth_type=ETH_IPv4),
               packet.parse.payload(offset),
               packet.parse.ip(offset) >>
               modify(ip_payload_offset=op_.add(offset, 'ip_ihl_bits')) >>
               packet.parse.payload('ip_payload_offset'))


parse_packet = packet.parse.ethernet(0) >> \
               if_(match(eth_type=ETH_VLAN),
                   packet.parse.ieee802_1q(112) >> parse_ip_other_payload(144),
                   parse_ip_other_payload(112))

# ###############################################################################
# Main policy
# ###############################################################################
def main():
    test1 = parse_packet >> \
            ((match(eth_srcmac=0x000000000001) >> modify(outport=2)) +
             (match(eth_srcmac=0x000000000002) >> modify(outport=1))) >> \
            if_(match(eth_type=0x0800),
                modify(ip_chksm=crc_('ip_ver', 'ip_ihl', 'ip_dscp', 'ip_ecn', 'ip_tlen',
                                     'ip_id', 'ip_flgs', 'ip_fo',
                                     'ip_ttl', 'ip_prtcl',
                                     'ip_srcip',
                                     'ip_dstip')),
                identity)

    return test1