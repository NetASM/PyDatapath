#!/usr/bin/python

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

import sys

from pydatapath.utils.bash import get_path

if __name__ == '__main__':
    # Check if pox is setup (i.e., located in the PYTHONPATH)
    if get_path('pox'): pass

    # Check if pydatapath is setup (i.e., located in the PYTHONPATH)
    if get_path('pydatapath'): pass

    # Stop listening for OpenFlow connections
    if '--no-openflow' not in sys.argv:
        sys.argv.insert(1, '--no-openflow')

    from pox.boot import boot

    boot()