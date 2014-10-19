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

import os
import sys
import re
import subprocess


def get_path(str):
    """
    Check if 'str' is in PYTHONPATH and return its absolute path.

    :param str:
    :return:
    """

    try:
        output = os.environ['PYTHONPATH']
    except:
        print 'Error: Unable to obtain PYTHONPATH'
        sys.exit(1)

    path = None

    for p in output.split(':'):
        if re.match('.*' + str + '.*/?$', p):
            path = os.path.abspath(p)
            break

    if path is None:
        print 'Error: ' + str + ' not found in PYTHONPATH'
        print output
        sys.exit(1)

    return path


def set_path(str):
    """
    Set 'str' in PYTHONPATH.

    :param str:
    :return:
    """

    try:
        output = os.environ['PYTHONPATH']
    except:
        print 'Error: Unable to obtain PYTHONPATH'
        sys.exit(1)

    os.environ['PYTHONPATH'] += ':' + str


def run_silent_cmd(cmd):
    """
    Run a command is silent mode.

    :param cmd:
    :return:
    """

    subprocess.call(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)