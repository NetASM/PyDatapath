__author__ = 'shahbaz'

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

from pydatapath.core import *


# ###############################################################################
# Known control policies
# ###############################################################################

class crc:
    # Calcuate IP header checksum
    @staticmethod
    def ip():
        return modify(ip_chksm=crc_('ip_ver', 'ip_ihl', 'ip_dscp', 'ip_ecn', 'ip_tlen',
                                   'ip_id', 'ip_flgs', 'ip_fo',
                                   'ip_ttl', 'ip_prtcl',
                                   'ip_srcip',
                                   'ip_dstip'))
