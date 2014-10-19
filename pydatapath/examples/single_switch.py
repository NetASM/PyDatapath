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

#!/usr/bin/python

__author__ = 'shahbaz'

import sys

from mininet.net import Mininet, CLI
from mininet.topo import SingleSwitchTopo
from mininet.log import setLogLevel
from pydatapath.mininet.node import ProgSwitch


def test():
    topo = SingleSwitchTopo(2)

    ProgSwitch.CTL_ADDRESS = "127.0.0.1"
    ProgSwitch.CTL_PORT = 7791

    net = Mininet(topo, switch=ProgSwitch, autoSetMacs=True)
    net.start()

    for s in net.switches:
        s.policy("pydatapath.modules.pass_through")

    if '--cli' in sys.argv:
        CLI(net)
    else:
        net.pingAll()
    net.stop()


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    test()
