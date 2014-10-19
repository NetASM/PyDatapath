__author__ = 'shahbaz'

from pydatapath.core import *

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

# ###############################################################################
# Known packet parsing policies
# ###############################################################################


class parse:
    # Ethernet
    @staticmethod
    def ethernet(offset=0):
        return extract(eth_dstmac=(offset, 0, 48),
                       eth_srcmac=(offset, 48, 48),
                       eth_type=(offset, 96, 16))


    # IEEE802_1Q (requires eth_type to be already extracted)
    @staticmethod
    def ieee802_1q(offset=112):
        return (extract(vlan_pcp=(offset, 0, 3),
                        vlan_cfi=(offset, 3, 1),
                        vlan_vid=(offset, 4, 12),
                        vlan_type=(offset, 16, 16)) >> modify(has_vlan=1))


    # IP packet (requires eth_type to be already extracted)
    @staticmethod
    def ip(offset=112):
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


    # TCP packet (require ip_prtcl to be already extracted)
    @staticmethod
    def tcp(offset=160):
        return (extract(tcp_srcport=(offset, 0, 16),
                        tcp_dstport=(offset, 16, 16),
                        tcp_seqno=(offset, 32, 32),
                        tcp_ackno=(offset, 64, 32),
                        tcp_do=(offset, 96, 4),
                        tcp_rsvd=(offset, 100, 3),
                        tcp_NS=(offset, 103, 1),
                        tcp_CWR=(offset, 104, 1),
                        tcp_ECE=(offset, 105, 1),
                        tcp_URG=(offset, 106, 1),
                        tcp_ACK=(offset, 107, 1),
                        tcp_PSH=(offset, 108, 1),
                        tcp_RST=(offset, 109, 1),
                        tcp_SYN=(offset, 110, 1),
                        tcp_FIN=(offset, 111, 1),
                        tcp_ws=(offset, 112, 16),
                        tcp_chksm=(offset, 128, 16),
                        tcp_up=(offset, 144, 16)) >> modify(has_tcp=1) >>

                modify(tcp_do_bits=op_.mul('tcp_do', 32)) >>

                if_(match(tcp_do=cmp_.gt(5)),
                    modify(tcp_op_len=op_.sub('tcp_do_bits', 160)) >>
                    extract(tcp_op=(offset, 160, 'tcp_op_len')) >> modify(has_tcp_op=1),
                    passthrough))


    # Packet payload
    @staticmethod
    def payload(offset):
        return extract(payload=(offset, 0, EOP))


# ###############################################################################
# Known packet deparsing policies
# ###############################################################################


class deparse:
    # Ethernet
    @staticmethod
    def ethernet(offset=0):
        return insert(eth_dstmac=(offset, 0, 48),
                      eth_srcmac=(offset, 48, 48),
                      eth_type=(offset, 96, 16))


    # IEEE802_1Q
    @staticmethod
    def ieee802_1q(offset=112):
        return insert(vlan_pcp=(offset, 0, 3),
                      vlan_cfi=(offset, 3, 1),
                      vlan_vid=(offset, 4, 12),
                      vlan_type=(offset, 16, 16))


    # IP packet (requires eth_type to be already extracted)
    @staticmethod
    def ip(offset=112):
        return (insert(ip_ver=(offset, 0, 4),
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
                       ip_dstip=(offset, 128, 32)) >>

                if_(match(has_ip_op=1),
                    insert(ip_op=(offset, 160, 'ip_op_len')),
                    passthrough))


    # TCP packet (require ip_prtcl to be already extracted)
    @staticmethod
    def tcp(offset=160):
        return (insert(tcp_srcport=(offset, 0, 16),
                       tcp_dstport=(offset, 16, 16),
                       tcp_seqno=(offset, 32, 32),
                       tcp_ackno=(offset, 64, 32),
                       tcp_do=(offset, 96, 4),
                       tcp_rsvd=(offset, 100, 3),
                       tcp_NS=(offset, 103, 1),
                       tcp_CWR=(offset, 104, 1),
                       tcp_ECE=(offset, 105, 1),
                       tcp_URG=(offset, 106, 1),
                       tcp_ACK=(offset, 107, 1),
                       tcp_PSH=(offset, 108, 1),
                       tcp_RST=(offset, 109, 1),
                       tcp_SYN=(offset, 110, 1),
                       tcp_FIN=(offset, 111, 1),
                       tcp_ws=(offset, 112, 16),
                       tcp_chksm=(offset, 128, 16),
                       tcp_up=(offset, 144, 16)) >>

                if_(match(has_tcp_op=1),
                    insert(tcp_op=(offset, 160, 'ip_op_len')),
                    passthrough))


    # Packet payload
    @staticmethod
    def payload(offset):
        return insert(payload=(offset, 0, EOF))