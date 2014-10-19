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

import subprocess

from mininet.node import Switch
from mininet.log import error
from pydatapath.utils.bash import get_path
from pydatapath.utils.bash import run_silent_cmd as run_cmd

path = get_path("pydatapath")


# ###############################################################################
# Programmable Switch class for Mininet
# ###############################################################################
class ProgSwitch(Switch):
    """ Programmable switch """

    # Default IP address and port to connect 'pydatapath'
    CTL_ADDRESS = "127.0.0.1"
    CTL_PORT = 7791

    def __init__(self, name, **kwargs):
        """

        :param name:
        :param kwargs:
        :return:
        """

        Switch.__init__(self, name, **kwargs)

        # Check if 'pydatapath' is running.
        try:
            output = subprocess.check_output('netstat -lnp | grep ' + str(ProgSwitch.CTL_PORT), shell=True).strip()
        except:
            error(
                "*** error: 'pydatapath' is not running at " + ProgSwitch.CTL_ADDRESS + "::" + str(ProgSwitch.CTL_PORT) + "\n")
            exit(1)

    def start(self, controllers):
        """
        Create a new switch in 'pydatapath' and setup its interfaces.

        :param controllers:
        :return:
        """

        cmd = 'python ' + path + '/pydatapath.py pydatapath.datapath.ctl --cmd="del-br ' + self.name + '"' + \
              ' --address=' + ProgSwitch.CTL_ADDRESS + ' --port=' + str(ProgSwitch.CTL_PORT)
        run_cmd(cmd)
        cmd = 'python ' + path + '/pydatapath.py pydatapath.datapath.ctl --cmd="add-br ' + self.name + '"' + \
              ' --address=' + ProgSwitch.CTL_ADDRESS + ' --port=' + str(ProgSwitch.CTL_PORT)
        run_cmd(cmd)

        for i in self.intfList():
            if self.name in i.name:
                cmd = 'python ' + path + '/pydatapath.py pydatapath.datapath.ctl --cmd="add-port ' + self.name + \
                      ' ' + i.name + '"' + \
                      ' --address=' + ProgSwitch.CTL_ADDRESS + ' --port=' + str(ProgSwitch.CTL_PORT)
                run_cmd(cmd)

    def stop(self):
        """

        :return:
        """

        cmd = 'python ' + path + '/pydatapath.py pydatapath.datapath.ctl --cmd="del-br ' + self.name + '"' + \
              ' --address=' + ProgSwitch.CTL_ADDRESS + ' --port=' + str(ProgSwitch.CTL_PORT)
        run_cmd(cmd)

    def policy(self, policy):
        """
        Add target.datapath policy.

        :param policy:
        :return:
        """

        cmd = 'python ' + path + '/pydatapath.py pydatapath.datapath.ctl --cmd="set-policy ' + self.name \
              + ' ' + policy + '"' + \
              ' --address=' + ProgSwitch.CTL_ADDRESS + ' --port=' + str(ProgSwitch.CTL_PORT)
        run_cmd(cmd)