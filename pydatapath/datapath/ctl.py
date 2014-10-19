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

# TODO: ctl dies when printing large policies (ERROR:lib.ioworker:Socket <Worker> error 104 during recv: Connection reset by peer)

"""
Simple target.datapath control framework for POX datapaths
"""

from pox.lib.ioworker.workers import *
from pox.lib.ioworker import *
from pox.lib.revent import *


# IOLoop for our IO workers
_ioloop = None

# Log
log = None


class CommandEvent(Event):
    """
    Event fired whenever a command is received
    """

    def __init__(self, worker, cmd):
        super(CommandEvent, self).__init__()
        self.worker = worker
        self.cmd = cmd

    @property
    def first(self):
        return self.cmd.strip().split()[0]

    @property
    def args(self):
        return self.cmd.strip().split()[1:]

    def __str__(self):
        return "<%s: %s>" % (self.worker, self.cmd)


class ServerWorker(TCPServerWorker, RecocoIOWorker):
    """
    Worker to accept connections
    """

    pass
    # TODO: Really should just add this to the ioworker package.


class Worker(RecocoIOWorker):
    """
    Worker to receive dpctl commands
    """

    def __init__(self, *args, **kw):
        super(Worker, self).__init__(*args, **kw)
        self._connecting = True
        self._buf = b''

    def _process(self, data):
        self._buf += data
        while '\n' in self._buf:
            fore, self._buf = self._buf.split('\n', 1)
            core.ctld.raiseEventNoErrors(CommandEvent, self, fore)

    def _handle_rx(self):
        self._buf += self.read()
        self._process(self.read())

    def _exec(self, msg):
        msg.split()


class Server(EventMixin):
    """
    Listens on a TCP socket for control
    """
    _eventMixin_events = set([CommandEvent])

    def __init__(self, port=7791):
        w = ServerWorker(child_worker_type=Worker, port=port)
        self.server_worker = w
        _ioloop.register_worker(w)


def create_server(port=7791):
    # Set up logging
    global log
    if not log:
        log = core.getLogger()

    # Set up IO loop
    global _ioloop
    if not _ioloop:
        _ioloop = RecocoIOLoop()
        # _ioloop.more_debugging = True
        _ioloop.start()

    c = Server(port=int(port))
    return c


def server(port=7791):
    c = create_server(int(port))
    core.register("ctld", c)


def launch(cmd, address=None, port=7791):
    core.quit()
    if not address:
        address = "127.0.0.1"
    import socket

    core.getLogger('core').setLevel(100)
    log = core.getLogger('ctl')
    try:
        s = socket.create_connection((address, port), timeout=2)
    except:
        log.error("Couldn't connect")
        return
    try:
        s.settimeout(2)
        s.send(cmd + "\n")
        d = s.recv(100*1024).strip()
        core.getLogger("ctl").info(d)
    except socket.timeout:
        log.warn("No response")
    except:
        log.exception("While communicating")
