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

from pydatapath.datapath import ctl

__author__ = 'shahbaz'

# ###############################################################################
# A programmable software switch/target.datapath
#
# Example:
# pydatapath.py pydatapath.target.datapath
# ###############################################################################

# TODO: add proper prints/logs for different events.

from ast import literal_eval
from Queue import Queue
from threading import Thread
from importlib import import_module

from pydatapath.core.language import Policy, tables
from pydatapath.core.packet import *
from pox.core import core
import pox.lib.pxpcap as pxpcap
from pox.lib.packet import ethernet


log = core.getLogger()

DEFAULT_CTL_PORT = 7791

_switches = {}


def launch(ctl_port=True):
    """

    :param ctl_port:
    :return:
    """

    if not pxpcap.enabled:
        raise RuntimeError("You need PXPCap to use this component")

    if ctl_port:
        if core.hasComponent('ctld'):
            raise RuntimeError("Only one ctl_port is allowed")

        if ctl_port is True:
            ctl_port = DEFAULT_CTL_PORT

        ctl.server(ctl_port)
        core.ctld.addListenerByName("CommandEvent", _do_ctl)


# ###############################################################################
# Control (CTL)
# ###############################################################################
def _do_ctl(event):
    """

    :param event:
    :return:
    """

    r = _do_ctl2(event)

    if r is None:
        r = "Okay."

    event.worker.send(r + "\n")


def _do_ctl2(event):
    """

    :param event:
    :return:
    """

    def errf(msg, *args):
        """

        :param msg:
        :param args:
        :return:
        """

        raise RuntimeError(msg % args)

    args = event.args

    def ra(low, high=None):
        """

        :param low:
        :param high:
        :return:
        """

        if high is None:
            high = low

        if len(args) < low or len(args) > high:
            raise RuntimeError("Wrong number of arguments")
        return False

    try:
        if event.first == "add-br":
            ra(1, 2)

            name = event.args[0]
            if name in _switches:
                raise RuntimeError("Switch already added")

            main = None

            if len(event.args) == 2:
                module_name = event.args[1]

                try:
                    module = import_module(module_name)
                except ImportError, e:
                    raise RuntimeError('Must be a valid python module\n' +
                                       'e.g, full module name,\n' +
                                       '     no .py suffix,\n' +
                                       '     located on the system PYTHONPATH\n' +
                                       '\n' +
                                       'Exception message for ImportError was:' + e.message)
                main = module.main

            sw = ProgSwitch(name, main)
            sw.start()
            _switches[name] = sw
        elif event.first == "del-br":
            ra(1)

            name = event.args[0]
            if name not in _switches:
                raise RuntimeError("No such switch")

            sw = _switches[name]
            sw.stop()
            del _switches[name]
        elif event.first == "add-port":
            ra(2)

            if event.args[0] not in _switches:
                raise RuntimeError("No such switch")
            sw = _switches[event.args[0]]
            p = args[1]

            sw.add_interface(p, start=True, on_error=errf)
        elif event.first == "del-port":
            ra(2)

            if event.args[0] not in _switches:
                raise RuntimeError("No such switch")
            sw = _switches[event.args[0]]
            p = args[1]

            sw.remove_interface(p)
        elif event.first == "set-policy":
            ra(2)

            if event.args[0] not in _switches:
                raise RuntimeError("No such switch")
            sw = _switches[event.args[0]]
            module_name = event.args[1]

            try:
                module = import_module(module_name)
            except ImportError, e:
                raise RuntimeError('Must be a valid python module\n' +
                                   'e.g, full module name,\n' +
                                   '     no .py suffix,\n' +
                                   '     located on the system PYTHONPATH\n' +
                                   '\n' +
                                   'Exception message for ImportError was:' + e.message)
            main = module.main

            if main:
                r_value = main()
                if isinstance(r_value, Policy):
                    sw.policy = r_value
                elif isinstance(r_value, tuple) and len(r_value) == 2:
                    if not isinstance(r_value[0], tables): raise TypeError("Invalid tables")
                    sw.tables = r_value[0]
                    if not isinstance(r_value[1], Policy): raise TypeError("Invalid policy")
                    sw.policy = r_value[1]
                else:
                    raise TypeError("Invalid target.datapath policy")
        elif event.first == "clr-policy":
            ra(1)

            if event.args[0] not in _switches:
                raise RuntimeError("No such switch")

            sw = _switches[event.args[0]]
            sw.tables = None
            sw.policy = None
        elif event.first == "add-entry":
            # usage: pydatapath.py pydatapath.target.datapath.ctl --cmd="add-entry s1 t0 0 {'eth_srcmac':0x1}"

            ra(4)

            if event.args[0] not in _switches:
                raise RuntimeError("No such switch")
            sw = _switches[event.args[0]]

            if not sw.policy: raise RuntimeError("Datapath policy not defined")
            if not sw.tables: raise RuntimeError("Datapath policy contains no tables")

            name = event.args[1]
            index = int(event.args[2])
            entry = literal_eval(event.args[3])

            sw.tables[name].add_entry(index, **entry)
        elif event.first == "del-entry":
            # usage: pydatapath.py pydatapath.target.datapath.ctl --cmd="del-entry s1 t0 0"

            ra(3)

            if event.args[0] not in _switches:
                raise RuntimeError("No such switch")
            sw = _switches[event.args[0]]

            if not sw.policy: raise RuntimeError("Datapath policy not defined")
            if not sw.tables: raise RuntimeError("Datapath policy contains no tables")

            name = event.args[1]
            index = int(event.args[2])

            sw.tables[name].del_entry(index)
        elif event.first == "show":
            ra(1)

            s = []
            for sw in _switches.values():
                s.append("Switch: %s" % (sw.name,))
                if event.args[0] == "ports":
                    for no, p in sw.ports.iteritems():
                        s.append("    %s: %s" % (no, p.device))
                if event.args[0] == "policy":
                    s.append("Policy: %s" % (repr(sw.policy),))
                if event.args[0] == "tables":
                    if sw.tables:
                        for t in sw.tables.available_tables():
                            s.append("Table: %s" % (t,))
                            s.append("    Fields: %s" % (sw.tables[t].fields,))
                            s.append("    Size: %s" % (sw.tables[t].size,))

            return "\n".join(s)
        else:
            raise RuntimeError("Unknown command")
    except Exception as e:
        log.exception("While processing command")
        return "Error: " + str(e)


# ###############################################################################
# Programmable Switch
# ###############################################################################
class ProgSwitch(object):
    def __init__(self, name, main=None, **kwargs):
        """
        Create a switch instance

        log_level (default to default_log_level) is level for this instance
        ports is a list of interface names

        :param kwargs:
        :return:
        """

        super(ProgSwitch, self).__init__()

        self.name = name
        self.tables = None
        self.policy = None

        if main:
            r_value = main()
            if isinstance(r_value, Policy):
                self.policy = r_value
            elif isinstance(r_value, tuple) and len(r_value) == 2:
                if not isinstance(r_value[0], tables): raise TypeError("Invalid tables")
                self.tables = r_value[0]
                if not isinstance(r_value[1], Policy): raise TypeError("Invalid policy")
                self.policy = r_value[1]
            else:
                raise TypeError("Invalid target.datapath policy")

        core.addListeners(self)

        self.port_no = 1
        self.ports = {}

        self.q = Queue()
        self.t = Thread(target=self._consumer_threadproc)

    def start(self):
        """

        :return:
        """

        self.t.start()

    def stop(self):
        """

        :return:
        """

        self.q.put(None)

    def add_interface(self, device, start=False, on_error=None):
        """

        :param device:
        :param start:
        :param on_error:
        :return:
        """

        if on_error is None:
            on_error = log.error

        devs = pxpcap.PCap.get_devices()
        if device not in devs:
            on_error("Device %s not available -- ignoring", device)
            return
        dev = devs[device]
        if dev.get('addrs', {}).get('ethernet', {}).get('addr') is None:
            on_error("Device %s has no ethernet address -- ignoring", device)
            return
        if dev.get('addrs', {}).get('AF_INET') is not None:
            on_error("Device %s has an IP address -- ignoring", device)
            return

        for no, p in self.ports.iteritems():
            if p.device == device:
                on_error("Device %s already added", device)

        port = pxpcap.PCap(device, callback=self._pcap_rx, start=False)
        port.set_direction(True, False)  # incoming traffic only
        port.port_no = self.port_no
        self.ports[self.port_no] = port

        self.port_no += 1

        if start:
            port.start()

        return port

    def remove_interface(self, device_or_num):
        """
        
        :param device_or_num:
        :return:
        """

        if isinstance(device_or_num, basestring):
            for no, p in self.ports.iteritems():
                if p.device == device_or_num:
                    self.remove_interface(no)
                    return
            raise ValueError("No such interface")

        p = self.ports[device_or_num]
        p.stop()
        del self.ports[device_or_num]
        self.port_no -= 1

    def _pcap_rx(self, port, packet, sec, usec, length):
        """

        :param port:
        :param packet:
        :param sec:
        :param usec:
        :param length:
        :return:
        """

        if port.port_no is None:
            return
        self.q.put((port.port_no, packet))

    def _consumer_threadproc(self):
        """

        :return:
        """
        timeout = 3

        while core.running:
            try:
                data = self.q.get(timeout=timeout)
            except:
                continue

            if data is None:
                # Signal to quit
                break

            batch = []
            while True:
                self.q.task_done()
                port_no, packet = data

                batch.append((port_no, packet))
                try:
                    data = self.q.get(block=False)
                except:
                    break

            core.callLater(self._rx_batch, batch)

    def _rx_batch(self, batch):
        for port_no, packet in batch:
            rx_packet = {"inport": port_no, "raw": packet}
            self._rx_packet(rx_packet)

    def _rx_packet(self, rx_packet):
        """
        process a dataplane packet

        data: an instance of packet data
        in_port: the integer port number
        packet_data: packed version of packet if available

        :param in_packet:
        :param in_port:
        :param packet_data:
        :return:
        """

        in_port = rx_packet['inport']
        in_packet = rx_packet['raw']

        p = self.ports.get(in_port)
        if p is None:
            log.warn("Got packet on missing port %i", in_port)
            return

        _packet = ethernet(in_packet)
        log.debug(_packet.dump())

        if self.policy:
            in_concrete_packet = rx_packet
            in_pyretic_packet = concrete_to_pydatapath(in_concrete_packet)

            out_pyretic_packets = self.policy.eval(in_pyretic_packet)

            out_concrete_packets = map(pydatapath_to_concrete, out_pyretic_packets)
            map(self._tx_packet, out_concrete_packets)
        else:
            log.warn("Switch (%s) target.datapath policy not defined", self.name)

    def _tx_packet(self, tx_packet):
        """
        send a packet out a single physical port

        :param packet:
        :param out_port:
        :return:
        """

        out_port = tx_packet['outport']
        out_packet = tx_packet['raw']

        port = self.ports.get(out_port)
        if not port:
            return
        port.inject(out_packet)

    def _handle_GoingDownEvent(self, event):
        """

        :param event:
        :return:
        """

        self.q.put(None)