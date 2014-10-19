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
# Main policy
# ###############################################################################
def main():
    # Maintain a list of dynamic tables.
    _tables = tables()

    # Dynamic table.
    _tables['t0'] = table.type.exact(fields=['eth_srcmac'], size=2)
    _tables['t0'].add_entry(0, eth_srcmac=0x000000000001)
    _tables['t0'].add_entry(1, eth_srcmac=0x000000000002)

    _tables['ct0'] = table.type.count(field='count', size=2)

    # Static table.
    t1 = table.type.simple(fields=['outport'], size=2)
    t1.add_entry(0, outport=2)
    t1.add_entry(1, outport=1)

    policy = extract(eth_dstmac=(0, 0, 48),
                     eth_srcmac=(0, 48, 48),
                     eth_type=(0, 96, 16),
                     payload=(0, 112, EOP)) >> \
             (match(index=_tables['t0']) >> modify(index=_tables['ct0']) >> modify(index=t1))

    return _tables, policy