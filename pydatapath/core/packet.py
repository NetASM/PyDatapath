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

from bitstring import BitArray

import pydatapath.utils as utils

# ###################################
# Constants
# ###################################

ETH_IPv4 = 0x0800
ETH_IPv6 = 0x86dd
ETH_VLAN = 0x8100
ETH_ARP = 0x0806
IP_PRTCL_TCP = 0x06


# ###################################
# Pyretic Packet
# ###################################
class Packet(object):
    __slots__ = ["header"]

    def __init__(self, state={}):
        self.header = utils.frozendict(state)

    def available_fields(self):
        return self.header.keys()

    def __eq__(self, other):
        return ( id(self) == id(other)
                 or ( isinstance(other, self.__class__)
                      and self.header == other.header ) )

    def __ne__(self, other):
        return not (self == other)

    def modifymany(self, d):
        add = {}
        delete = []
        for k, v in d.items():
            if v is None:
                delete.append(k)
            else:
                add[k] = v
        return Packet(self.header.update(add).remove(delete))

    def modify(self, **kwargs):
        return self.modifymany(kwargs)

    def virtual(self, layer, item):
        v = self.header.get(('v_%s_%s' % (layer, item)), None)

        if v is None:
            raise KeyError(item)

        return v

    def __getitem__(self, item):
        return self.header[item]

    def __hash__(self):
        return hash(self.header)

    def __repr__(self):
        import hashlib

        fixed_fields = {}
        fixed_fields['location'] = ['switch', 'inport', 'outport']
        fixed_fields['vlocation'] = ['vswitch', 'vinport', 'voutport']
        fixed_fields['source'] = ['srcip', 'srcmac']
        fixed_fields['dest'] = ['dstip', 'dstmac']
        order = ['location', 'vlocation', 'source', 'dest']
        all_fields = self.header.keys()
        outer = []
        size = max(map(len, self.header) or map(len, order) or [len('md5'), 0]) + 3
        # ## LOCATION, VLOCATION, SOURCE, and DEST - EACH ON ONE LINE
        for fields in order:
            inner = ["%s:%s" % (fields, " " * (size - len(fields)))]
            all_none = True
            for field in fixed_fields[fields]:
                try:
                    all_fields.remove(field)
                except:
                    pass
                try:
                    inner.append(repr(self.header[field]))
                    all_none = False
                except KeyError:
                    inner.append('None')
            if not all_none:
                outer.append('\t'.join(inner))
        # ## MD5 OF PAYLOAD
        field = 'raw'
        outer.append("%s:%s%s" % ('md5',
                                  " " * (size - len(field)),
                                  hashlib.md5(self.header[field]).hexdigest()))
        all_fields.remove(field)
        # ## ANY ADDITIONAL FIELDS
        for field in sorted(all_fields):
            try:
                if self.header[field]:
                    outer.append("%s:%s\t%s" % (field,
                                                " " * (size - len(field)),
                                                repr(self.header[field])))
            except KeyError:
                pass
        return "\n".join(outer)


def is_virtual_header(header):
    """

    :param header:
    :return:
    """

    return not (header['offset'] or header['length'])


# ######################################
# Packet Marshalling and Unmarshalling
# ######################################
def concrete_to_pydatapath(concrete_packet):
    """

    :param concrete_packet:
    :return:
    """

    # Add offset/length information in the header along with its value.
    _concrete_packet = {}
    _concrete_packet["inport"] = utils.frozendict({"offset": None, "length": None,
                                                   "value": concrete_packet["inport"]})

    _concrete_packet["raw"] = utils.frozendict(
        {"offset": 0, "length": 8 * len(concrete_packet["raw"]),  # length in bits
         "value": concrete_packet["raw"]})

    # Create a pydatapath packet from concrete packet.
    pydatapath_packet = Packet(utils.frozendict())
    return pydatapath_packet.modifymany(_concrete_packet)


def pydatapath_to_concrete(pydatapath_packet):
    """

    :param packet:
    :return:
    """

    # TODO: this can be optimized
    length = 0
    for header in pydatapath_packet.available_fields():
        if is_virtual_header(pydatapath_packet[header]) or header is 'raw': continue
        length += pydatapath_packet[header]['length']

    raw_packet = BitArray(length=length)

    if not length:
        raw_packet.bytes = pydatapath_packet['raw']['value']
    else:
        # Apply header updates to the raw packet.
        for header in pydatapath_packet.available_fields():
            if is_virtual_header(pydatapath_packet[header]) or header is 'raw': continue
            (offset, length, value) = (pydatapath_packet[header]['offset'], pydatapath_packet[header]['length'],
                                       pydatapath_packet[header]['value'])
            raw_packet[offset:(offset + length)] = value


    # Create concrete packet from pydatapath packet.
    concrete_packet = {}
    concrete_packet['outport'] = pydatapath_packet['outport']["value"]
    concrete_packet['raw'] = raw_packet.bytes

    return concrete_packet