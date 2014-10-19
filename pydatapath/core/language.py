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

from bitstring import BitArray

from pydatapath.utils import singleton
import pydatapath.utils as utils
import pydatapath.utils.algorithms as algorithms

# ###############################################################################
# Policy Language                                                               #
# ###############################################################################
class Policy(object):
    """
    Top-level abstract class for policies.
    All Pyretic policies have methods for

    - evaluating on a single packet.
    - compilation to a switch Classifier
    """

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        raise NotImplementedError

    def __add__(self, policy):
        """
        The parallel composition operator.

        :param policy: the Policy to the right of the operator
        :type policy: Policy
        :rtype: Parallel
        """
        if isinstance(policy, parallel):
            return parallel([self] + policy.policies)
        else:
            return parallel([self, policy])

    def __rshift__(self, other):
        """
        The sequential composition operator.

        :param pol: the Policy to the right of the operator
        :type pol: Policy
        :rtype: Sequential
        """
        if isinstance(other, sequential):
            return sequential([self] + other.policies)
        else:
            return sequential([self, other])

    def __eq__(self, other):
        """Syntactic equality."""
        raise NotImplementedError

    def __ne__(self, other):
        """Syntactic inequality."""
        return not (self == other)

    def name(self):
        return self.__class__.__name__

    def __repr__(self):
        return "%s : %d" % (self.name(), id(self))


class Filter(Policy):
    """
    Abstact class for filter policies.
    A filter Policy will always either

    - pass packets through unchanged
    - drop them

    No packets will ever be modified by a Filter.
    """

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        raise NotImplementedError

    def __or__(self, policy):
        """
        The Boolean OR operator.

        :param policy: the filter Policy to the right of the operator
        :type policy: Filter
        :rtype: Union
        """
        if isinstance(policy, Filter):
            return union([self, policy])
        else:
            raise TypeError

    def __and__(self, policy):
        """
        The Boolean AND operator.

        :param policy: the filter Policy to the right of the operator
        :type policy: Filter
        :rtype: Intersection
        """
        if isinstance(policy, Filter):
            return intersection([self, policy])
        else:
            raise TypeError

    def __sub__(self, policy):
        """
        The Boolean subtraction operator.

        :param policy: the filter Policy to the right of the operator
        :type policy: Filter
        :rtype: Difference
        """
        if isinstance(policy, Filter):
            return difference(self, policy)
        else:
            raise TypeError

    def __invert__(self):
        """
        The Boolean negation operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: negate
        """
        return negate([self])


class Singleton(Filter):
    """Abstract policy from which Singletons descend"""
    pass


@singleton
class identity(Singleton):
    """The identity policy, leaves all packets unchanged."""

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        return {packet}

    def intersect(self, other):
        return other

    def covers(self, other):
        return True

    def __eq__(self, other):
        return ( id(self) == id(other)
                 or (isinstance(other, match) and len(other.map) == 0))

    def __repr__(self):
        return "identity"


passthrough = identity  # Imperative alias
true = identity  # Logic alias
all_packets = identity  # Matching alias


@singleton
class drop(Singleton):
    """The drop policy, produces the empty set of packets."""

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        return set()

    def intersect(self, other):
        return self

    def covers(self, other):
        return False

    def __eq__(self, other):
        return id(self) == id(other)

    def __repr__(self):
        return "drop"


none = drop
false = drop  # Logic alias
no_packets = drop  # Matching alias


@singleton
class controller(Singleton):
    def eval(self, packet):
        return set()

    def __eq__(self, other):
        return id(self) == id(other)

    def __repr__(self):
        return "Controller"


to_cpu = controller


class match(Filter):
    """
    Match on all specified fields.
    Matched packets are kept, non-matched packets are dropped.

    :param *args: field matches in argument format
    :param **kwargs: field matches in keyword-argument format
    """

    def __init__(self, *args, **kwargs):

        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = utils.frozendict(dict(*args, **kwargs))
        super(match, self).__init__()

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """

        headers = {}

        for header, value in self.map.items():
            try:
                if isinstance(value, table) and value.is_type_exact():
                    # Check for repeated fields in the tables and the map.
                    if set(value.fields).intersection(set(self.map) - {header}):
                        raise TypeError
                    index = value.eval(packet)
                    if index is None:
                        return set()
                    headers[header] = utils.frozendict({'offset': None, 'length': None,
                                                        'value': index})
                elif isinstance(value, cmp_):
                    if not value.eval(header, packet):
                        return set()
                elif isinstance(value, int) or isinstance(value, long):
                    _value = packet[header]['value']
                    if value is None or value != _value:
                        return set()
                elif isinstance(value, str):
                    _value = packet[value]['value']
                    __value = packet[header]['value']
                    if _value is None or _value != __value:
                        return set()
                else:  # Not supported type
                    raise TypeError
            except:
                if value is not None:
                    return set()

        return {packet.modifymany(headers)}

    def __eq__(self, other):
        return ((isinstance(other, match) and self.map == other.map)
                or (other == identity and len(self.map) == 0))

    def intersect(self, policy):

        def _intersect_ip(ipfx, opfx):
            most_specific = None
            if ipfx in opfx:
                most_specific = ipfx
            elif opfx in ipfx:
                most_specific = opfx
            else:
                most_specific = None
            return most_specific

        if policy == identity:
            return self
        elif policy == drop:
            return drop
        elif not isinstance(policy, match):
            raise TypeError
        fs1 = set(self.map.keys())
        fs2 = set(policy.map.keys())
        shared = fs1 & fs2
        most_specific_src = None
        most_specific_dst = None

        for f in shared:
            if (f == 'srcip'):
                most_specific_src = _intersect_ip(self.map[f], policy.map[f])
                if most_specific_src is None:
                    return drop
            elif (f == 'dstip'):
                most_specific_dst = _intersect_ip(self.map[f], policy.map[f])
                if most_specific_dst is None:
                    return drop
            elif (self.map[f] != policy.map[f]):
                return drop

        d = self.map.update(policy.map)

        if most_specific_src is not None:
            d = d.update({'srcip': most_specific_src})
        if most_specific_dst is not None:
            d = d.update({'dstip': most_specific_dst})

        return match(d)

    def __and__(self, policy):
        if isinstance(policy, match):
            return self.intersect(policy)
        else:
            return super(match, self).__and__(policy)

    # ## hash : unit -> int
    def __hash__(self):
        return hash(self.map)

    def covers(self, other):
        # Return identity if self matches every packet that other matches (and maybe more).
        # eg. if other is specific on any field that self lacks.
        if other == identity and len(self.map.keys()) > 0:
            return False
        elif other == identity:
            return True
        elif other == drop:
            return True
        if set(self.map.keys()) - set(other.map.keys()):
            return False
        for (f, v) in self.map.items():
            other_v = other.map[f]
            if (f == 'srcip' or f == 'dstip'):
                if v != other_v:
                    if not other_v in v:
                        return False
            elif v != other_v:
                return False
        return True

    def __repr__(self):
        return "match: %s" % ' '.join(map(str, self.map.items()))


class modify(Policy):
    """
    Modify on all specified fields to specified values.

    :param *args: field assignments in argument format
    :param **kwargs: field assignments in keyword-argument format
    """

    def __init__(self, *args, **kwargs):
        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = dict(*args, **kwargs)
        super(modify, self).__init__()

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """

        headers = {}

        for header, value in self.map.items():
            # Check for repeated fields in table and map.
            if header in headers: raise TypeError
            if isinstance(value, table):
                if value.is_type_simple():
                    try:
                        index = packet[header]['value']
                        for _header, _value in value[index].items():
                            self._eval(packet, headers, _header, _value)
                    except:
                        raise TypeError
                elif value.is_type_count():
                    try:
                        index = packet[header]['value']
                        value.eval(index)
                    except:
                        raise TypeError
                else:  # Not supported type
                    raise TypeError
            elif isinstance(value, crc_) or isinstance(value, op_) or isinstance(value, hash_):
                self._eval(packet, headers, header, value.eval(packet))
            elif isinstance(value, int) or isinstance(value, long):
                self._eval(packet, headers, header, value)
            elif isinstance(value, str):
                self._eval(packet, headers, header, packet[value]['value'])
            else:  # Not supported type
                raise TypeError

        return {packet.modifymany(headers)}

    def _eval(self, packet, headers, header, value):
        """

        :param packet:
        :param headers:
        :return:
        """

        try:
            if packet[header]:
                headers[header] = utils.frozendict(
                    {'offset': packet[header]['offset'], 'length': packet[header]['length'],
                     'value': value})
        except:
            headers[header] = utils.frozendict({'offset': None, 'length': None,
                                                'value': value})

    def __repr__(self):
        return "modify: %s" % ' '.join(map(str, self.map.items()))

    def __eq__(self, other):
        return (isinstance(other, modify)
                and (self.map == other.map))


EOP = -1


class extract(Policy):
    """
    Extract specified fields from the header and store them in the local map.
    """

    def __init__(self, *args, **kwargs):
        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = dict(*args, **kwargs)
        super(extract, self).__init__()

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        headers = {}
        raw_value = BitArray(bytes=packet['raw']['value'])

        for (header, (base, offset, length)) in self.map.items():
            if isinstance(base, str):
                base = packet[base]['value']
            if isinstance(offset, str):
                offset = packet[offset]['value']
            if isinstance(length, str):
                length = packet[length]['value']

            offset = base + offset
            length = packet['raw']['length'] - offset if length == EOP else length
            headers[header] = utils.frozendict({'offset': offset, 'length': length,
                                                'value': raw_value[offset:(offset + length)].uint})

        return {packet.modifymany(headers)}

    def __repr__(self):
        return "extract: %s" % ' '.join(map(str, self.map.items()))

    def __eq__(self, other):
        return (isinstance(other, extract)
                and (self.map == other.map))


EOF = -1


class insert(Policy):
    """
    Insert specified fields to the header from the local map.
    """

    def __init__(self, *args, **kwargs):
        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = dict(*args, **kwargs)
        super(insert, self).__init__()

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """

        headers = {}

        for (header, (base, offset, length)) in self.map.items():
            if isinstance(base, str):
                base = packet[base]['value']
            if isinstance(offset, str):
                offset = packet[offset]['value']
            if isinstance(length, str):
                length = packet[length]['value']

            offset = base + offset
            length = packet[header]['length'] if length == EOF else length
            headers[header] = utils.frozendict({'offset': offset, 'length': length,
                                                'value': packet[header]['value']})

        return {packet.modifymany(headers)}

    def __repr__(self):
        return "insert: %s" % ' '.join(map(str, self.map.items()))

    def __eq__(self, other):
        return (isinstance(other, extract)
                and (self.map == other.map))


# ###############################################################################
# Combinator Policies                                                           #
# ###############################################################################
class CombinatorPolicy(Policy):
    """
    Abstract class for policy combinators.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """
    # ## init : List Policy -> unit
    def __init__(self, policies=[]):
        self.policies = list(policies)
        super(CombinatorPolicy, self).__init__()

    def __repr__(self):
        return "%s:\n%s" % (self.name(), utils.repr_plus(self.policies))

    def __eq__(self, other):
        return ( self.__class__ == other.__class__
                 and self.policies == other.policies )


class negate(CombinatorPolicy, Filter):
    """
    Combinator that negates the input policy.

    :param policies: the policies to be negated.
    :type policies: list Filter
    """

    def eval(self, packet):
        """
        evaluate this policy on a single packet

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        if self.policies[0].eval(packet):
            return set()
        else:
            return {packet}


class parallel(CombinatorPolicy):
    """
    Combinator for several policies in parallel.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """

    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return drop
        else:
            rv = super(parallel, self).__new__(parallel, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(parallel, self).__init__(policies)

    def __add__(self, policy):
        if isinstance(policy, parallel):
            return parallel(self.policies + policy.policies)
        else:
            return parallel(self.policies + [policy])

    def eval(self, packet):
        """
        evaluates to the set union of the evaluation
        of self.policies on packet

        :param packet: the packet on which to be evaluated
        :typacketpkt: Packet
        :rtype: set Packet
        """
        output = set()
        for policy in self.policies:
            output |= policy.eval(packet)
        return output


class union(parallel, Filter):
    """
    Combinator for several filter policies in parallel.

    :param policies: the policies to be combined.
    :type policies: list Filter
    """

    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return drop
        else:
            rv = super(parallel, self).__new__(union, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(union, self).__init__(policies)

    # ## or : Filter -> Filter
    def __or__(self, policy):
        if isinstance(policy, union):
            return union(self.policies + policy.policies)
        elif isinstance(policy, Filter):
            return union(self.policies + [policy])
        else:
            raise TypeError


class sequential(CombinatorPolicy):
    """
    Combinator for several policies in sequence.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """

    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return identity
        else:
            rv = super(sequential, self).__new__(sequential, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(sequential, self).__init__(policies)

    def __rshift__(self, pol):
        if isinstance(pol, sequential):
            return sequential(self.policies + pol.policies)
        else:
            return sequential(self.policies + [pol])

    def eval(self, packet):
        """
        evaluates to the set union of each policy in
        self.policies on each packet in the output of the
        previous.  The first policy in self.policies is
        evaled on packet.

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        prev_output = {packet}
        output = prev_output
        for policy in self.policies:
            if not prev_output:
                return set()
            if policy == identity:
                continue
            if policy == drop:
                return set()
            output = set()
            for p in prev_output:
                output |= policy.eval(p)
            prev_output = output
        return output


class intersection(sequential, Filter):
    """
    Combinator for several filter policies in sequence.

    :param policies: the policies to be combined.
    :type policies: list Filter
    """

    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return identity
        else:
            rv = super(sequential, self).__new__(intersection, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(intersection, self).__init__(policies)

    # ## and : Filter -> Filter
    def __and__(self, policy):
        if isinstance(policy, intersection):
            return intersection(self.policies + policy.policies)
        elif isinstance(policy, Filter):
            return intersection(self.policies + [policy])
        else:
            raise TypeError


# ###############################################################################
# Derived Policies                                                              #
# ###############################################################################
class DerivedPolicy(Policy):
    """
    Abstract class for a policy derived from another policy.

    :param policy: the internal policy (assigned to self.policy)
    :type policy: Policy
    """

    def __init__(self, policy=identity):
        self.policy = policy
        self._classifier = None
        super(DerivedPolicy, self).__init__()

    def eval(self, packet):
        """
        evaluates to the output of self.policy.

        :param packet: the packet on which to be evaluated
        :type packet: Packet
        :rtype: set Packet
        """
        return self.policy.eval(packet)

    def __repr__(self):
        return "[DerivedPolicy]\n%s" % repr(self.policy)

    def __eq__(self, other):
        return (self.__class__ == other.__class__
                and (self.policy == other.policy))


class difference(DerivedPolicy, Filter):
    """
    The difference between two filter policies..

    :param f1: the minuend
    :type f1: Filter
    :param f2: the subtrahend
    :type f2: Filter
    """

    def __init__(self, f1, f2):
        self.f1 = f1
        self.f2 = f2
        super(difference, self).__init__(~f2 & f1)

    def __repr__(self):
        return "difference:\n%s" % utils.repr_plus([self.f1, self.f2])


class if_(DerivedPolicy):
    """
    if pred holds, t_branch, otherwise f_branch.

    :param pred: the predicate
    :type pred: Filter
    :param t_branch: the true branch policy
    :type pred: Policy
    :param f_branch: the false branch policy
    :type pred: Policy
    """

    def __init__(self, pred, t_branch, f_branch=identity):
        self.pred = pred
        self.t_branch = t_branch
        self.f_branch = f_branch
        super(if_, self).__init__((self.pred >> self.t_branch) +
                                  ((~self.pred) >> self.f_branch))

    def eval(self, packet):
        if self.pred.eval(packet):
            return self.t_branch.eval(packet)
        else:
            return self.f_branch.eval(packet)

    def __repr__(self):
        return "if\n%s\nthen\n%s\nelse\n%s" % (utils.repr_plus([self.pred]),
                                               utils.repr_plus([self.t_branch]),
                                               utils.repr_plus([self.f_branch]))


# ###############################################################################
# Table Policies                                                                #
# ###############################################################################
class tables(object):
    def __init__(self, **kwargs):
        self._tables = kwargs

        for n, t in self._tables.items():
            t.name = n

    def available_tables(self):
        return self._tables.keys()

    def __getitem__(self, name):
        if name not in self._tables:
            raise TypeError("No such table")

        return self._tables[name]

    def __setitem__(self, name, table):
        if name in self._tables:
            raise TypeError("Table with this name already exists")

        self._tables[name] = table
        table.name = name

    def __repr__(self):
        return self._tables.__repr__()


class table(object):
    def __init__(self, fields, size):
        """

        :param fields:
        :param size:
        :return:
        """

        if len(fields) == 0:
            raise TypeError("Invalid fields")
        if size <= 0:
            raise TypeError("Invalid table size")

        self.name = "static"
        self.fields = fields
        self.size = size

        self._table = [None] * self.size

    def __getitem__(self, index):
        """

        :param index:
        :return:
        """

        return self._table[index]

    def add_entry(self, *args, **kwargs):
        """

        :param args:
        :param kwargs:
        :return:
        """

        if len(args) != 1: raise TypeError("Invalid args or index not defined")
        index = args[0]

        if len(kwargs) == 0: raise RuntimeError("Table entry is empty")
        entry = kwargs

        if not (set(entry.keys()) == set(self.fields)):
            raise TypeError("Invalid table entry")
        self._table[index] = entry

    def del_entry(self, index):
        """

        :param index:
        :return:
        """

        self._table[index] = None

    def is_type_exact(self):
        """
        Check if tables is valid for match policy.

        :param tables:
        :return:
        """

        if "_exact" in str(type(self)):
            return True
        return False

    def is_type_simple(self):
        """
        Check if tables is valid for modify policy.

        :param tables:
        :return:
        """

        if "_simple" in str(type(self)):
            return True
        return False

    def is_type_count(self):
        """
        Check if tables is valid for modify policy.

        :param tables:
        :return:
        """

        if "_count" in str(type(self)):
            return True
        return False

    class type(object):

        @staticmethod
        def exact(fields, size):
            """
            Exact table.

            :param fields:
            :param size:
            :return:
            """

            class _exact(table):

                def __init__(self, fields, size):
                    """

                    :param fields:
                    :param size:
                    :return:
                    """

                    super(_exact, self).__init__(fields, size)

                def eval(self, packet):
                    """

                    :param packet:
                    :return:
                    """

                    for entry in self._table:
                        if entry is None: continue

                        if (set(self.fields) - set(packet.available_fields())):
                            raise TypeError

                        if all(map(lambda x: packet[x]['value'] == entry[x], self.fields)):
                            return self._table.index(entry)

                def __repr__(self):
                    """

                    :return:
                    """

                    return "'[table: %s, (type: exact, fields: %s, size: %s, values: %s)]" % (
                        self.name, self.fields.__repr__(), str(self.size), self._table.__repr__())

            return _exact(fields, size)

        @staticmethod
        def simple(fields, size):
            """
            Simple table.

            :param fields:
            :param size:
            :return:
            """

            class _simple(table):
                def __init__(self, fields, size):
                    """

                    :param fields:
                    :param size:
                    :return:
                    """

                    super(_simple, self).__init__(fields, size)

                def __repr__(self):
                    """

                    :return:
                    """

                    return "'[table: %s, (type: simple, fields: %s, size: %s, values: %s)]" % (
                        self.name, self.fields.__repr__(), str(self.size), self._table.__repr__())

            return _simple(fields, size)

        @staticmethod
        def count(field='count', size=None):
            """
            Count table.
            # TODO: add bit size constraint

            :param size:
            :return:
            """

            class _count(table):
                def __init__(self, fields, size):
                    """

                    :param fields:
                    :param size:
                    :return:
                    """

                    if len(fields) != 1:
                        raise TypeError

                    super(_count, self).__init__(fields, size)

                    self._table = [0] * self.size

                def eval(self, index):
                    """

                    :param packet:
                    :return:
                    """

                    self._table[index] += 1

                def __repr__(self):
                    """

                    :return:
                    """

                    return "'[table: %s, (type: count, fields: %s, size: %s, values: %s)]" % (
                        self.name, self.fields.__repr__(), str(self.size), self._table.__repr__())

            if size is None:
                raise TypeError

            return _count([field], size)


# ###############################################################################
# CRC Policy                                                                    #
# ###############################################################################
class crc_(object):
    def __init__(self, *args):
        """

        :param args:
        :return:
        """

        if len(args) == 0:
            raise TypeError
        # TODO: probably add a check for field repetition.
        self.fields = args

    def eval(self, packet):
        """

        :param packet:
        :return:
        """

        a = utils.get_bitarray(packet, self.fields)

        return algorithms.crc16(a.bytes)

    def __repr__(self):
        """

        :return:
        """

        return "crc: %s" % ' '.join(map(str, self.fields))


# ###############################################################################
# Comparison Operation Policies (>, <, ==)                                     #
# ###############################################################################
class cmp_(object):
    @staticmethod
    def gt(*args):
        class _gt(op_):
            def __init__(self, *args):
                """

                :param args:
                :return:
                """

                if len(args) != 1:
                    raise TypeError

                self.field = args

            def eval(self, field, packet):
                """

                :param packet:
                :return:
                """

                l_val = packet[field]['value']
                r_val = packet[self.field]['value'] if isinstance(self.field, str) else self.field

                return l_val > r_val

            def __repr__(self):
                """

                :return:
                """

                return "gt : %s" % ' '.join(map(str, self.field))

        return _gt(*args)

    @staticmethod
    def lt(*args):
        class _lt(op_):
            def __init__(self, *args):
                """

                :param args:
                :return:
                """

                if len(args) != 1:
                    raise TypeError

                self.field = args

            def eval(self, field, packet):
                """

                :param packet:
                :return:
                """

                l_val = packet[field]['value']
                r_val = packet[self.field]['value'] if isinstance(self.field, str) else self.field

                return l_val < r_val

            def __repr__(self):
                """

                :return:
                """

                return "lt : %s" % ' '.join(map(str, self.field))

        return _lt(*args)


# ###############################################################################
# Operation Policies (Add, Subtract, Shift)                                     #
# ###############################################################################
class op_(object):
    @staticmethod
    def add(*args):
        class _add(op_):
            def __init__(self, *args):
                """

                :param args:
                :return:
                """

                if len(args) != 2:
                    raise TypeError

                self.fields = args

            def eval(self, packet):
                """

                :param packet:
                :return:
                """

                l_val = packet[self.fields[0]]['value'] if isinstance(self.fields[0], str) else self.fields[0]
                r_val = packet[self.fields[1]]['value'] if isinstance(self.fields[1], str) else self.fields[1]

                return l_val + r_val

            def __repr__(self):
                """

                :return:
                """

                return "add : %s" % ' '.join(map(str, self.fields))

        return _add(*args)

    @staticmethod
    def sub(*args):
        class _sub(op_):
            def __init__(self, *args):
                """

                :param args:
                :return:
                """

                if len(args) != 2:
                    raise TypeError

                self.fields = args

            def eval(self, packet):
                """

                :param packet:
                :return:
                """

                l_val = packet[self.fields[0]]['value'] if isinstance(self.fields[0], str) else self.fields[0]
                r_val = packet[self.fields[1]]['value'] if isinstance(self.fields[1], str) else self.fields[1]

                return l_val - r_val

            def __repr__(self):
                """

                :return:
                """

                return "sub : %s" % ' '.join(map(str, self.fields))

        return _sub(*args)

    @staticmethod
    def mul(*args):
        class _mul(op_):
            def __init__(self, *args):
                """

                :param args:
                :return:
                """

                if len(args) != 2:
                    raise TypeError

                self.fields = args

            def eval(self, packet):
                """

                :param packet:
                :return:
                """

                l_val = packet[self.fields[0]]['value'] if isinstance(self.fields[0], str) else self.fields[0]
                r_val = packet[self.fields[1]]['value'] if isinstance(self.fields[1], str) else self.fields[1]

                return l_val * r_val

            def __repr__(self):
                """

                :return:
                """

                return "mul : %s" % ' '.join(map(str, self.fields))

        return _mul(*args)

    @staticmethod
    def inc(*args):
        class _inc(op_):
            def __init__(self, *args):
                """

                :param args:
                :return:
                """

                if len(args) != 1:
                    raise TypeError
                self.field = args[0]

            def eval(self, packet):
                return packet[self.field]['value'] + 1

            def __repr__(self):
                """

                :return:
                """

                return "inc : %s" % ' '.join(map(str, self.field))

        return _inc(*args)

    @staticmethod
    def dec(*args):
        class _dec(op_):
            def __init__(self, *args):
                """

                :param args:
                :return:
                """

                if len(args) != 1:
                    raise TypeError
                self.field = args[0]

            def eval(self, packet):
                return packet[self.field]['value'] - 1

            def __repr__(self):
                """

                :return:
                """

                return "dec : %s" % ' '.join(map(str, self.field))

        return _dec(*args)


# ###############################################################################
# Hash Policy                                                                   #
# ###############################################################################
class hash_(object):
    def __init__(self, *args):
        """

        :param args:
        :return:
        """

        if len(args) == 0:
            raise TypeError
        # TODO: probably add a check for field repetition.
        self.fields = args

    def eval(self, packet):
        """

        :param packet:
        :return:
        """

        a = utils.get_bitarray(packet, self.fields)

        return hash(a.uint)

    def __repr__(self):
        """

        :return:
        """

        return "hash: %s" % ' '.join(map(str, self.fields))

