"""A high-level interface for reading and writing BER/DER data.

Currently, only a few ASN.1 types are supported. This implementation
is based on the rules that are specified in X.690 (08/2015).

Note: there are probably better BER readers/writers out there - I just wrote
this in order to get familiar with ASN.1 and BER.
"""

import struct
import sys
from io import BytesIO


class BERIOError(Exception):
    pass


class ValidationError(Exception):
    pass


class DecodingError(Exception):
    pass


def read_exact(readable, count):
    data = bytearray()
    while count:
        d = readable.read(count)
        if not d:
            raise BERIOError('premature EOF')
        data.extend(d)
        count -= len(d)
    return bytes(data)


def write_exact(writable, buf):
    while buf:
        count = writable.write(buf)
        if not count:
            raise BERIOError('0-length write')
        buf = buf[count:]


class Validator:
    def _validate(condition, msg, *args, **kwargs):
        if not condition:
            raise ValidationError(msg.format(*args, **kwargs))

    def validate_tag_number(self, tag_number):
        self._validate(tag_number < 0, "illegal tag: {}", tag_number)

    def validate_tag_class(self, tag_class):
        self._validate(0 <= tag_class <= 3, 'illegal class: {}', tag_class)

    def validate_length(self, length):
        self._validate(length >= 0, "length must be non-negative: {}", length)


def validate(*items):
    def _decorator(meth):
        def _validate_and_process(self, *args):
            if len(args) < len(items):
                raise ValueError('to few arguments')
            for item, arg in zip(items, args):
                validation = getattr(self._validator,
                                     "validate_{}".format(item))
                # the validation is supposed to raise an exception in case of
                # an error
                validation(arg)
            return meth(self, *args)
        return _validate_and_process
    return _decorator


class Tag:
    # tag class, tag_number, constructed
    END_OF_CONTENTS = (0, 0, False)
    BOOLEAN = (0, 1, False)
    INTEGER = (0, 2, False)
    ENUMERATED = (0, 10, False)
    BITSTRING_PRIMITIVE = (0, 3, False)
    BITSTRING_CONSTRUCTED = (0, 3, True)
    OCTETSTRING_PRIMITIVE = (0, 4, False)
    OCTETSTRING_CONSTRUCTED = (0, 4, True)
    NULL = (0, 5, False)
    SEQUENCE = (0, 16, True)
    OID = (0, 6, False)


class Base:
    def __init__(self, validator=None):
        if validator is None:
            validator = Validator()
        self._validator = validator

    def _unused_bits(self, byte):
        unused = 0
        for i in range(8):
            if (byte >> i) & 1:
                break
            unused += 1
        return unused


class SequenceEncodingMapper:
    def __init__(self, encoder):
        self._map = {
            bool: encoder.write_boolean,
            int: encoder.write_integer,
            bytes: encoder.write_octetstring,
            None.__class__: encoder.write_null,
        }

    def is_sequence(self, item):
        return isinstance(item, (tuple, list))

    def map(self, item):
        return self._map[item.__class__]


class Encoder(Base):
    def __init__(self, writable, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._writables = []
        self._push_writable(writable)

    def _write(self, data):
        write_exact(self._writables[-1], data)

    def _pack(self, pformat, *args):
        return self._write(struct.pack(pformat, *args))

    def _push_writable(self, writable):
        self._writables.append(writable)

    def _pop_writable(self):
        return self._writables.pop()

    @validate('tag_class', 'tag_number')
    def write_tag(self, tag_class, tag_number, constructed=False):
        cval = 0
        if constructed:
            cval = 32
        if tag_number <= 30:
            self._pack('B', tag_class << 6 | cval | tag_number)
            return
        self._pack('B', tag_class << 6 | cval | 31)
        octets = []
        while tag_number:
            octets.append(128 | (tag_number & 127))
            tag_number >>= 6
        octets[0] &= 127
        octets.reverse()
        self._pack("{}B".format(len(octets)), *octets)

    @validate('length')
    def write_length(self, length):
        if length <= 127:
            self._pack('B', length)
            return
        octets = []
        while length:
            octets.append(length & 255)
            length >>= 8
        if len(octets) >= 127:
            # 127 is ok, but SHALL not be used (see X.690 8.1.3.5 (c))
            raise ValueError('too many length octets')
        octets.reverse()
        self._pack('B', 128 | len(octets))
        self._pack("{}B".format(len(octets)), *octets)

    def write_indefinite_length(self):
        self._pack('B', 128)

    def write_boolean(self, value):
        self.write_tag(*Tag.BOOLEAN)
        self.write_length(1)
        self._pack('B', 255 if value else 0)

    def _write_integer(self, tag, num):
        self.write_tag(*tag)
        if not num:
            self.write_length(1)
            self._pack('B', 0)
            return
        # probably the dumbest way to calculate a two's complement...
        signed = num < 0
        if signed:
            num *= -1
        octets = []
        c = 1
        while num:
            val = num & 255
            num >>= 8
            if signed:
                val = (~val & 255) + c
                c = 0
                if val >= 256:
                    c = 1
                    val &= 255
            octets.append(val)
        if c and signed:
            # c == 1 implies num == 0
            raise RuntimeError('c must not be 1')
        if not signed and (octets[-1] & 128):
            octets.append(0)
        elif signed and not (octets[-1] & 128):
            octets.append(255)
        octets.reverse()
        self.write_length(len(octets))
        self._pack("{}B".format(len(octets)), *octets)

    def write_integer(self, num):
        self._write_integer(Tag.INTEGER, num)

    def write_enumerated(self, num):
        self._write_integer(Tag.ENUMERATED, num)

    def write_bitstring(self, raw):
        # This behavior is a bit debatable; if the underlying bitstring
        # type has a NamedBitList, this behavior is OK (see X.680 22.7).
        # Note: trailing zeros are perfectly fine! (see also X.690 8.6.2.2)
        while raw and not raw[-1]:
            raw.pop()
        # for now, we just support the length restricted, primitive encoding
        self.write_tag(*Tag.BITSTRING_PRIMITIVE)
        length = 1 + len(raw)
        self.write_length(length)
        # due to the removal of trailing zeros, we have 0 <= unused <= 7
        unused = self._unused_bits(raw[-1]) if raw else 0
        self._pack("{}B".format(length), unused, *raw)

    def write_octetstring(self, raw):
        # for now, we just support the length restricted, primitive encoding
        self.write_tag(*Tag.OCTETSTRING_PRIMITIVE)
        length = len(raw)
        self.write_length(length)
        self._pack("{}B".format(length), *raw)

    def write_null(self, value=None):
        if value is not None:
            raise ValueError('value must be None')
        self.write_tag(*Tag.NULL)
        self.write_length(0)

    def write_sequence(self, sequence, mapper=None):
        # this implementation conforms to DER (that's why we use a definite
        # length for sequences) => works only for moderately small sequences
        # and subsequences
        if mapper is None:
            mapper = SequenceEncodingMapper(self)
        iterators = [iter(sequence)]
        self._push_writable(BytesIO())
        seen = {}
        while iterators:
            iterator = iterators.pop()
            exhausted = True
            for item in iterator:
                if mapper.is_sequence(item):
                    if seen.get(id(item), False):
                        raise ValueError('cannot serialize cyclic sequence')
                    seen[id(item)] = True
                    iterators.append(iterator)
                    iterators.append(iter(item))
                    self._push_writable(BytesIO())
                    exhausted = False
                    break
                meth = mapper.map(item)
                meth(item)
            if exhausted:
                bio = self._pop_writable()
                self.write_tag(*Tag.SEQUENCE)
                self.write_length(len(bio.getvalue()))
                self._write(bio.getvalue())

    def write_sequence_of(self, sequence, mapper=None):
        # no type checking etc.
        self.write_sequence(sequence, mapper)

    def write_oid(self, oid):
        if len(oid) < 2:
            raise ValueError('oid must have at least two arcs')
        if min(oid) < 0:
            raise ValueError('all arcs must be non-negative')
        root, second, oid = oid[0], oid[1], oid[2:]
        if root not in (0, 1, 2):
            raise ValueError("illegal root: {}".format(root))
        if root in (0, 1) and second > 39:
            raise ValueError("illegal arcs: {} {}".format(root, second))
        octets = []
        oid.insert(0, root * 40 + second)
        for arc in oid:
            if not arc:
                octets.append(arc)
                continue
            arc_octets = []
            while arc:
                arc_octets.append(128 | (arc & 127))
                arc >>= 7
            arc_octets[0] &= 127
            arc_octets.reverse()
            octets.extend(arc_octets)
        self.write_tag(*Tag.OID)
        length = len(octets)
        self.write_length(length)
        self._pack("{}B".format(length), *octets)


class SequenceDecodingBuilder:
    def __init__(self, decoder):
        self._tag_map = {
            Tag.BOOLEAN: decoder.read_boolean,
            Tag.INTEGER: decoder.read_integer,
            Tag.BITSTRING_PRIMITIVE: decoder.read_bitstring,
            Tag.BITSTRING_CONSTRUCTED: decoder.read_bitstring,
            Tag.OCTETSTRING_PRIMITIVE: decoder.read_octetstring,
            Tag.OCTETSTRING_CONSTRUCTED: decoder.read_octetstring,
            Tag.NULL: decoder.read_null,
            Tag.OID: decoder.read_oid
        }
        self._data = [[]]

    def begin_sequence(self):
        new = []
        self._data[-1].append(new)
        self._data.append(new)

    def end_sequence(self):
        self._data.pop()

    def handle(self, tag):
        meth = self._map(tag)
        value = meth()
        self._data[-1].append(value)
        return value

    def _map(self, tag):
        return self._tag_map[tag]

    def build(self):
        return self._data[0][0]


class SequenceDecodingPrintBuilder(SequenceDecodingBuilder):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._indent = 0

    def begin_sequence(self):
        super().begin_sequence()
        self._print('[')
        self._indent += 1

    def end_sequence(self):
        super().end_sequence()
        self._indent -= 1
        self._print(']')

    def handle(self, tag):
        value = super().handle(tag)
        self._print(value)
        return value

    def _print(self, value):
        print('{}{}'.format('\t' * self._indent, value))


class LimitedReader:
    def __init__(self, readable, limit=None):
        self._readable = readable
        self._limit = limit

    def is_unlimited(self):
        return self._limit is None

    def is_eof(self):
        # end of limit
        return not self.is_unlimited() and not self._limit

    def read(self, count):
        if self.is_unlimited():
            return self._readable.read(count)
        limit = self._limit
        if count > limit:
            raise RuntimeError("limit exceeded: {}, {}".format(limit, count))
        data = self._readable.read(count)
        if len(data) > limit:
            raise RuntimeError("read returned more than count bytes/data")
        self._limit -= len(data)
        return data


class Decoder(Base):
    def __init__(self, readable, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._readers = [LimitedReader(readable)]
        self._peeked_tag = None

    def _push_reader(self, limit=None):
        self._readers.append(LimitedReader(self._readers[-1], limit))

    def _pop_reader(self):
        return self._readers.pop()

    def _unpack(self, pformat, *args):
        return struct.unpack(pformat, *args)

    def _read(self, count):
        data = read_exact(self._readers[-1], count)
        return self._unpack("{}B".format(len(data)), data)

    def read_tag(self):
        if self._peeked_tag is not None:
            tag = self._peeked_tag
            self._peeked_tag = None
            return tag
        octet, = self._read(1)
        tag_class = (octet & 192) >> 6
        constructed = (octet & 32) == 32
        if (octet & 31) != 31:
            tag_number = octet & 31
            if tag_number > 30:
                raise DecodingError("illegal tag octet: {}".format(octet))
            return tag_class, tag_number, constructed
        tag_number = 0
        while True:
            octet, = self._read(1)
            # TODO: overflow check
            tag_number = tag_number << 6 | (octet & 127)
            if not (octet & 128):
                break
        return tag_class, tag_number, constructed

    def peek_tag(self):
        if self._peeked_tag is None:
            self._peeked_tag = self.read_tag()
        return self._peeked_tag

    def read_length(self):
        octet, = self._read(1)
        if octet <= 127:
            return octet
        num_octets = octet & 127
        if not num_octets:
            # indefinite length => EOC octet required
            return -1
        length = 0
        for octet in self._read(num_octets):
            length = (length << 8) | octet
        return length

    def read_boolean(self):
        tag = self.read_tag()
        if tag != Tag.BOOLEAN:
            raise DecodingError("expected boolean tag, got: {}".format(tag))
        length = self.read_length()
        if length != 1:
            raise DecodingError("expected length 1, got: {}".format(length))
        octet, = self._read(1)
        return octet != 0

    def _read_integer(self, expected_tag):
        actual_tag = self.read_tag()
        if actual_tag != expected_tag:
            raise DecodingError("expected tag: {}, got: {}".format(
                expected_tag, actual_tag))
        length = self.read_length()
        if not length:
            raise DecodingError('expected a positive length')
        num = 0
        for octet in self._read(length):
            num = (num << 8) | octet
        val = 1 << (length * 8 - 1)
        if num & val:
            # undo two's complement
            num -= 2 * val
        return num

    def read_integer(self):
        return self._read_integer(Tag.INTEGER)

    def read_enumerated(self):
        return self._read_integer(Tag.ENUMERATED)

    def _read_bitstring_octetstring(self, primitive_tag, constructed_tag,
                                    primitive_handler):
        raw = bytearray()
        level = 0
        initial = True
        while level or initial:
            initial = False
            tag = self.read_tag()
            length = self.read_length()
            if tag == primitive_tag:
                raw.extend(primitive_handler(length))
            elif tag == constructed_tag:
                if length != -1:
                    raise DecodingError('expected indefinite length')
                level += 1
            elif tag == Tag.END_OF_CONTENTS:
                if length:
                    raise DecodingError('EOC requires 0 length')
                if not level:
                    raise DecodingError('premature end of contents')
                level -= 1
            else:
                msg = "unexpected tag: exp: {}, got {}".format(primitive_tag,
                                                               tag)
                raise DecodingError(msg)
        return raw

    def _bitstring_primitive_handler(self, length):
        if length == -1:
            msg = 'primitive bitstring encoding requires definite length'
            raise DecodingError(msg)
        octets = list(self._read(length))
        unused = octets.pop(0)
        if not octets:
            return bytearray()
        unused_act = self._unused_bits(octets[-1])
        if unused > unused_act:
            msg = "unused bit violation: {} vs. {}".format(unused, unused_act)
            raise DecodingError(msg)
        # note that octets can have trailing zeros (it is perfectly valid if it
        # consists only of zeros)
        return bytearray(octets)

    def read_bitstring(self):
        handler = self._bitstring_primitive_handler
        return self._read_bitstring_octetstring(Tag.BITSTRING_PRIMITIVE,
                                                Tag.BITSTRING_CONSTRUCTED,
                                                handler)

    def read_octetstring(self):
        def handler(length):
            return bytearray(self._read(length))

        return self._read_bitstring_octetstring(Tag.OCTETSTRING_PRIMITIVE,
                                                Tag.OCTETSTRING_CONSTRUCTED,
                                                handler)

    def read_null(self):
        tag = self.read_tag()
        if tag != Tag.NULL:
            raise DecodingError("expected null tag, got {}".format(tag))
        if self.read_length() != 0:
            raise DecodingError('null encoding requires 0 length')
        return None

    def read_end_of_contents(self):
        tag = self.read_tag()
        if tag != Tag.END_OF_CONTENTS:
            raise DecodingError("expected EOC tag, got {}".format(tag))
        length = self.read_length()
        if length != 0:
            raise DecodingError('EOC encoding requires 0 length')

    def read_sequence(self, builder=None):
        if builder is None:
            # this only works for a moderately small sequence because the
            # SequenceDecodingBuilder reads everything into memory - for a
            # larger sequence, write an appropriate builder...
            builder = SequenceDecodingBuilder(self)
        tag = self.peek_tag()
        if tag != Tag.SEQUENCE:
            raise DecodingError("expected sequence tag, got{}".format(tag))
        # it holds: len(self._readers) == 1 and the reader is unlimited
        initial = True
        while len(self._readers) > 1 or initial:
            restart = False
            # pop exhausted readers
            while self._readers[-1].is_eof():
                self._pop_reader()
                builder.end_sequence()
                restart = True
            if restart:
                continue
            tag = self.peek_tag()
            if tag == Tag.SEQUENCE:
                initial = False
                self.read_tag()
                length = self.read_length()
                self._push_reader(length if length != -1 else None)
                builder.begin_sequence()
                continue
            elif tag == Tag.END_OF_CONTENTS:
                self.read_end_of_contents()
                reader = self._pop_reader()
                builder.end_sequence()
                if not reader.is_unlimited():
                    raise RuntimeError('EOC but no unlimited reader')
                continue
            builder.handle(tag)
        return builder.build()

    def read_sequence_of(self, builder=None):
        # no type checking etc.
        return self.read_sequence(builder)

    def read_oid(self):
        tag = self.read_tag()
        if tag != Tag.OID:
            raise DecodingError("expected oid tag, got: {}".format(tag))
        length = self.read_length()
        if length < 0:
            # see X.690 8.1.3.2 (a)
            raise DecodingError('definite length required')
        elif not length:
            raise DecodingError('0-length oid')
        octets = list(self._read(length))
        oid = []
        while octets:
            is_series = True
            num = 0
            while octets and is_series:
                val = octets.pop(0)
                is_series = val & 128
                num = (num << 7) | (val & 127)
            if not octets and is_series:
                raise DecodingError('premature end of oid component series')
            oid.append(num)
        first = oid.pop(0)
        root = 0
        if first >= 80:
            first -= 80
            root = 2
        elif first >= 40:
            first -= 40
            root = 1
        oid.insert(0, root)
        oid.insert(1, first)
        return oid


class Bitstring:
    """A very naive (wrt. memory consumption) bitstring implementation"""
    def __init__(self, *ones, raw=None):
        if ones and raw is not None:
            raise ValueError('ones and raw are mutually exclusive')
        if raw is None:
            self._data = bytearray()
        else:
            self._data = raw
        for bit in ones:
            self.set(bit, 1)

    def _get_bit(self, bit):
        idx = int(bit / 8)
        off = 7 - (bit % 8)
        if len(self._data) < idx + 1:
            return 0
        return 1 if self._data[idx] & (1 << off) else 0

    def _set_bit(self, bit, value):
        idx = int(bit / 8)
        off = 7 - (bit % 8)
        length = len(self._data)
        if length < idx + 1:
            self._data.extend([0 for i in range(idx + 1 - length)])
        byte = self._data[idx]
        if value:
            byte |= (1 << off)
        else:
            byte &= ~(1 << off)
        self._data[idx] = byte

    def set(self, bit, value):
        self._set_bit(bit, value)

    def get(self, bit):
        return self._get_bit(bit)

    def clear(self, bit):
        self.set(bit, 0)

    def serialize(self):
        return self._data

    @classmethod
    def parse(cls, raw):
        return cls(raw=raw)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("usage: {} <filename>".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], 'rb') as f:
        dec = Decoder(f)
        dec.read_sequence(SequenceDecodingPrintBuilder(dec))
