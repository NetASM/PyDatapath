__author__ = 'shahbaz'

# ###############################################################################
# Utility functions                                                             #
# ###############################################################################


import sys
from functools import wraps
from logging import StreamHandler

from bitstring import BitArray


def singleton(f):
    """

    :param f:
    :return:
    """
    return f()


def cached(f):
    """

    :param f:
    :return:
    """

    @wraps(f)
    def wrapper(*args):
        """

        :param args:
        :return:
        """

        try:
            return wrapper.cache[args]
        except KeyError:
            wrapper.cache[args] = v = f(*args)
            return v

    wrapper.cache = {}
    return wrapper


class frozendict(object):
    __slots__ = ["_dict", "_cached_hash"]

    def __init__(self, new_dict=None, **kwargs):
        """

        :param new_dict:
        :param kwargs:
        :return:
        """

        self._dict = dict()
        if new_dict is not None:
            self._dict.update(new_dict)
        self._dict.update(kwargs)

    def update(self, new_dict=None, **kwargs):
        """

        :param new_dict:
        :param kwargs:
        :return:
        """

        d = self._dict.copy()

        if new_dict is not None:
            d.update(new_dict)
        d.update(kwargs)

        return self.__class__(d)

    def remove(self, ks):
        """

        :param ks:
        :return:
        """

        d = self._dict.copy()
        for k in ks:
            if k in d:
                del d[k]
        return self.__class__(d)

    def pop(self, *ks):
        """

        :param ks:
        :return:
        """

        result = []
        for k in ks:
            result.append(self[k])
        result.append(self.remove(*ks))
        return result

    def __repr__(self):
        """

        :return:
        """

        return repr(self._dict)

    def __iter__(self):
        """

        :return:
        """

        return iter(self._dict)

    def __contains__(self, key):
        """

        :param key:
        :return:
        """

        return key in self._dict

    def keys(self):
        """

        :return:
        """

        return self._dict.keys()

    def values(self):
        """

        :return:
        """

        return self._dict.values()

    def items(self):
        """

        :return:
        """

        return self._dict.items()

    def iterkeys(self):
        """

        :return:
        """

        return self._dict.iterkeys()

    def itervalues(self):
        """

        :return:
        """

        return self._dict.itervalues()

    def iteritems(self):
        """

        :return:
        """

        return self._dict.iteritems()

    def get(self, key, default=None):
        """

        :param key:
        :param default:
        :return:
        """

        return self._dict.get(key, default)

    def __getitem__(self, item):
        """

        :param item:
        :return:
        """

        return self._dict[item]

    def __hash__(self):
        """

        :return:
        """

        try:
            return self._cached_hash
        except AttributeError:
            h = self._cached_hash = hash(frozenset(self._dict.items()))
            return h

    def __eq__(self, other):
        """

        :param other:
        :return:
        """

        return self._dict == other._dict

    def __ne__(self, other):
        """

        :param other:
        :return:
        """

        return self._dict != other._dict

    def __len__(self):
        """

        :return:
        """

        return len(self._dict)


def indent_str(s, indent=4):
    """

    :param s:
    :param indent:
    :return:
    """

    return "\n".join(indent * " " + i for i in s.splitlines())


def repr_plus(ss, indent=4, sep="\n", prefix=""):
    """

    :param ss:
    :param indent:
    :param sep:
    :param prefix:
    :return:
    """

    if isinstance(ss, basestring):
        ss = [ss]
    return indent_str(sep.join(prefix + repr(s) for s in ss), indent)


class LockStreamHandler(StreamHandler):
    '''Relies on a multiprocessing.Lock to serialize multiprocess writes to a
    stream.'''

    def __init__(self, lock, stream=sys.stderr):
        """

        :param lock:
        :param stream:
        :return:
        """

        self.lock = lock
        super(MultiprocessStreamHandler, self).__init__(stream)

    def emit(self, record):
        """
        Acquire the lock before emitting the record.

        :param record:
        :return:
        """
        self.lock.acquire()
        super(LockStreamHandler, self).emit(record)
        self.lock.release()


class QueueStreamHandler(StreamHandler):
    """
    Relies on a multiprocessing.Lock to serialize multiprocess writes to a
    stream.
    """

    def __init__(self, queue, stream=sys.stderr):
        """

        :param queue:
        :param stream:
        :return:
        """

        self.queue = queue
        super(QueueStreamHandler, self).__init__(stream)

    def emit(self, record):
        """
        Acquire the lock before emitting the record.

        :param record:
        :return:
        """

        self.queue.put(record)


def get_bitarray(packet, fields):
    """

    :param packet:
    :param fields:
    :return:
    """

    o = 0
    a = BitArray()
    for h in fields:
        l = packet[h]['length']
        a[o:(o + l)] = packet[h]['value']
        o += l

    return a