import unittest
import os
from io import BytesIO

from keyutils.ber import (Encoder, Decoder, Bitstring, Tag,
                          SequenceDecodingBuilder)


class TestBer(unittest.TestCase):
    def _assert_tag(self, *tag):
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_tag(*tag)
        bio.seek(0, os.SEEK_SET)
        dec = Decoder(bio)
        actual_tag = dec.read_tag()
        self.assertEqual(tag, actual_tag)

    def test_tag(self):
        """Encode and decode tags"""
        self._assert_tag(0, 0, False)
        self._assert_tag(1, 0, True)
        self._assert_tag(2, 0, True)
        self._assert_tag(3, 0, True)
        self._assert_tag(2, 15, False)
        self._assert_tag(2, 15, True)
        self._assert_tag(1, 30, True)
        self._assert_tag(1, 30, False)
        self._assert_tag(1, 31, True)
        self._assert_tag(1, 31, False)
        self._assert_tag(3, 256, False)
        self._assert_tag(3, 337, False)
        self._assert_tag(3, 1337, False)
        self._assert_tag(1, 471133, True)
        self._assert_tag(0, 424213379998101, False)
        self._assert_tag(2, 999999999999999999191848484777000, True)

    def _assert_function(self, what, data):
        bio = BytesIO()
        enc = Encoder(bio)
        enc_meth = getattr(enc, "write_{}".format(what))
        enc_meth(data)
        bio.seek(0, os.SEEK_SET)
        dec = Decoder(bio)
        dec_meth = getattr(dec, "read_{}".format(what))
        actual_data = dec_meth()
        self.assertEqual(data, actual_data)

    def _assert_length(self, length):
        self._assert_function('length', length)

    def test_length(self):
        """Encode and decode various lengths"""
        self._assert_length(0)
        self._assert_length(42)
        self._assert_length(127)
        self._assert_length(128)
        self._assert_length(255)
        self._assert_length(256)
        self._assert_length(1337)
        self._assert_length(0xdeadbeef)
        self._assert_length(18345736593467563457631984)
        # indefinite test
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_indefinite_length()
        self.assertEqual(b'\x80', bio.getvalue())
        dec = Decoder(BytesIO(b'\x80'))
        self.assertEqual(-1, dec.read_length())

    def _assert_boolean(self, value):
        self._assert_function('boolean', value)

    def test_boolean(self):
        """Encode and decode booleans"""
        self._assert_boolean(True)
        self._assert_boolean(False)
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_boolean(42)
        self.assertEqual(b'\x01\x01\xff', bio.getvalue())
        dec = Decoder(BytesIO(b'\x01\x01\x01'))
        self.assertTrue(dec.read_boolean())

    def _assert_integer(self, value):
        self._assert_function('integer', value)

    def test_integer(self):
        """Encode and decode integers"""
        self._assert_integer(0)
        self._assert_integer(1)
        self._assert_integer(-1)
        self._assert_integer(127)
        self._assert_integer(-127)
        self._assert_integer(128)
        self._assert_integer(-128)
        self._assert_integer(129)
        self._assert_integer(-129)
        self._assert_integer(256)
        self._assert_integer(-256)
        self._assert_integer(255)
        self._assert_integer(-255)
        self._assert_integer(-((127 << 8) | 127))
        self._assert_integer(-((128 << 8) | 127))
        self._assert_integer(-((129 << 8) | 128))
        self._assert_integer(131458482384583458435)
        self._assert_integer(-2143484848482149324532945943159)
        self._assert_integer(131458482384583458435)

    def _assert_enumerated(self, value):
        self._assert_function('enumerated', value)

    def test_enumerated(self):
        """Encode and decode enumerated values"""
        self._assert_enumerated(0)
        self._assert_enumerated(88484348)

    def test_bitstring_cls(self):
        """Test the bitstring class"""
        bs = Bitstring(0, 1, 2, 5, 32, 255, 127)
        # test ones
        self.assertEqual(1, bs.get(0))
        self.assertEqual(1, bs.get(1))
        self.assertEqual(1, bs.get(2))
        self.assertEqual(1, bs.get(5))
        self.assertEqual(1, bs.get(32))
        self.assertEqual(1, bs.get(255))
        self.assertEqual(1, bs.get(127))
        # test some zeros
        self.assertEqual(0, bs.get(3))
        self.assertEqual(0, bs.get(31))
        self.assertEqual(0, bs.get(33))
        self.assertEqual(0, bs.get(256))
        self.assertEqual(0, bs.get(128))
        self.assertEqual(0, bs.get(4848483434))
        # set
        bs.set(0, 0)
        bs.set(1, 0)
        bs.set(2, 1)
        bs.set(3, 1)
        bs.set(5555, 1)
        bs.set(4444, 0)
        bs.set(44449, 0)
        self.assertEqual(0, bs.get(0))
        self.assertEqual(0, bs.get(1))
        self.assertEqual(1, bs.get(2))
        self.assertEqual(1, bs.get(3))
        self.assertEqual(1, bs.get(5555))
        self.assertEqual(0, bs.get(4444))
        self.assertEqual(0, bs.get(44449))
        # clear
        bs.clear(1)
        bs.clear(127)
        bs.clear(128)
        self.assertEqual(0, bs.get(1))
        self.assertEqual(0, bs.get(127))
        self.assertEqual(0, bs.get(128))
        # serialize
        bs = Bitstring(7, 3, 32, 1, 59, 60, 9)
        expected = bytearray([81, 64, 0, 0, 128, 0, 0, 24])
        self.assertEqual(expected, bs.serialize())
        self.assertEqual(expected, Bitstring.parse(bs.serialize()).serialize())
        # parse
        bs = Bitstring.parse(bytearray([0x0A, 0x18, 0x3F]))
        # 0
        self.assertEqual(0, bs.get(0))
        self.assertEqual(0, bs.get(1))
        self.assertEqual(0, bs.get(2))
        self.assertEqual(0, bs.get(3))
        # A
        self.assertEqual(1, bs.get(4))
        self.assertEqual(0, bs.get(5))
        self.assertEqual(1, bs.get(6))
        self.assertEqual(0, bs.get(7))
        # 1
        self.assertEqual(0, bs.get(8))
        self.assertEqual(0, bs.get(9))
        self.assertEqual(0, bs.get(10))
        self.assertEqual(1, bs.get(11))
        # 8
        self.assertEqual(1, bs.get(12))
        self.assertEqual(0, bs.get(13))
        self.assertEqual(0, bs.get(14))
        self.assertEqual(0, bs.get(15))
        # 3
        self.assertEqual(0, bs.get(16))
        self.assertEqual(0, bs.get(17))
        self.assertEqual(1, bs.get(18))
        self.assertEqual(1, bs.get(19))
        # F
        self.assertEqual(1, bs.get(20))
        self.assertEqual(1, bs.get(21))
        self.assertEqual(1, bs.get(22))
        self.assertEqual(1, bs.get(23))

    def _assert_bitstring(self, value):
        self._assert_function('bitstring', value)

    def test_bitstring_primitive(self):
        """Encode and decode bitstrings (primitive)"""
        self._assert_bitstring(bytearray())
        # see X.690 (8.6.4.2)
        raw = bytearray([0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0])
        self._assert_bitstring(raw)
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_bitstring(raw)
        self.assertEqual(b'\x03\x07\x04\x0A\x3B\x5F\x29\x1C\xD0',
                         bio.getvalue())
        # 0-length bitstring (remove trailing zeros)
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_bitstring(bytearray([0, 0, 0]))
        self.assertEqual(b'\x03\x01\x00', bio.getvalue())

    def test_bitstring_constructed(self):
        """Decode a bitstring (constructed)"""
        # see X.690 (8.6.4.2)
        raw = bytearray([0x0A, 0x3B, 0x5F, 0x29, 0x1C, 0xD0])
        bio = BytesIO(
            b'\x23\x80\x03\x03\x00\x0A\x3B\x03\x05\x04\x5F\x29\x1C\xD0\x00\x00'
        )
        dec = Decoder(bio)
        self.assertEqual(raw, dec.read_bitstring())
        # nested encoding
        bio = BytesIO(
            # noqa: E131
            b'\x23\x80'
                b'\x23\x80'
                    b'\x23\x80'
                        b'\x23\x80'
                            b'\x03\x01\x00'             # empty bitstring
                            b'\x03\x04\01\xAF\x00\x3E'
                            b'\x03\x02\x00\xFF'
                        b'\x00\x00'
                        b'\x03\x03\x07\x11\x80'
                    b'\x00\x00'
                    b'\x23\x80'
                        b'\x03\x02\x00\x0F'
                    b'\x00\x00'
                b'\x00\x00'
                b'\x23\x80'
                b'\x00\x00'
                b'\x23\x80'
                b'\x03\x01\x00'                         # empty bitstring
                b'\x00\x00'
                b'\x03\x04\x02\xEA\xAF\x4C'
            b'\x00\x00'
        )
        dec = Decoder(bio)
        self.assertEqual(b'\xAF\x00\x3E\xFF\x11\x80\x0F\xEA\xAF\x4C',
                         dec.read_bitstring())

    def _assert_octetstring(self, value):
        self._assert_function('octetstring', value)

    def test_octetstring_primitive(self):
        """Encode and decode an octetstring (primitive)"""
        self._assert_octetstring(b'adsfkiasdf\xFF\x00\x99fd4iowe$$/w4i')
        self._assert_octetstring(b'')
        self._assert_octetstring(b'\x00')
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_octetstring(b'foobar')
        self.assertEqual(b'\x04\x06foobar', bio.getvalue())

    def test_octetstring_constructed(self):
        """Decode an octetstring (constructed)"""
        bio = BytesIO(
            # noqa: E131
            b'\x24\x80'
                b'\x24\x80'
                b'\x04\x0A0123456789'
                b'\x00\x00'
                b'\x24\x80'
                    b'\x04\x03foo'
                    b'\x04\x06\x03\x04\x02\xEA\xAF\x4C'
                    b'\x24\x80'
                        b'\x04\x05abcde'
                        b'\x24\x80'
                        b'\x00\x00'
                        b'\x24\x80'
                        b'\x00\x00'
                        b'\x04\x02\x00\x00'
                    b'\x00\x00'
                b'\x00\x00'
                b'\x24\x80'
                b'\x24\x80'
                b'\x00\x00'
                b'\x00\x00'
                b'\x24\x80'
                b'\x00\x00'
            b'\x00\x00'
        )
        dec = Decoder(bio)
        self.assertEqual(b'0123456789foo\x03\x04\x02\xEA\xAF\x4Cabcde\x00\x00',
                         dec.read_octetstring())

    def test_null(self):
        """Encode and decode a null value"""
        self._assert_function('null', None)
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_null()
        enc.write_null(None)
        self.assertEqual(b'\x05\x00\x05\x00', bio.getvalue())

    def _assert_sequence(self, value):
        self._assert_function('sequence', value)

    def test_sequence(self):
        """Encode and decode sequence values"""
        self._assert_sequence([])
        self._assert_sequence([4, 5, True, b'an octet string',
                              [], [b'', 42, 1337, [[], [], [[[]]]]], [4711]])
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_sequence([b'foo', [], [True, [], [None, False, b'x']], None])
        self.assertEqual(
            # noqa: E131
            b'\x30\x1A'
                b'\x04\x03foo'
                b'\x30\x00'
                b'\x30\x0F'
                    b'\x01\x01\xFF'
                    b'\x30\x00'
                    b'\x30\x08'
                        b'\x05\x00'
                        b'\x01\x01\x00'
                        b'\x04\x01x'
                b'\x05\x00',
            bio.getvalue())
        # indefinite length
        bio = BytesIO(b'\x30\x80\x04\x03foo\x30\x80\x00\x00\x05\x00\x00\x00')
        dec = Decoder(bio)
        self.assertEqual([b'foo', [], None], dec.read_sequence())
        # mix indefinite + definite lengths
        bio = BytesIO(
            # noqa: E131
            b'\x30\x80'
                b'\x30\x0F'
                    b'\x30\x0D'
                        b'\x05\x00'
                        b'\x04\x03foo'
                        b'\x30\x80'
                            b'\x05\x00'
                        b'\x00\x00'
            b'\x00\x00'
        )
        dec = Decoder(bio)
        self.assertEqual([[[None, b'foo', [None]]]], dec.read_sequence())
        # "excess" end of contents is not considered
        bio = BytesIO(b'\x30\x80\x00\x00\x00\x00')
        dec = Decoder(bio)
        self.assertEqual([], dec.read_sequence())
        dec.read_end_of_contents()

    def test_sequence_custom_builder(self):
        """Test custom builder in Decoder.read_sequence"""
        class TracingSequenceDecodingBuilder(SequenceDecodingBuilder):
            def __init__(self, *args, **kwargs):
                super(TracingSequenceDecodingBuilder, self).__init__(*args,
                                                                     **kwargs)
                self.trace = []

            def begin_sequence(self):
                super(TracingSequenceDecodingBuilder, self).begin_sequence()
                self.trace.append('[')

            def end_sequence(self):
                super(TracingSequenceDecodingBuilder, self).end_sequence()
                self.trace.append(']')

            def handle(self, tag):
                data = super(TracingSequenceDecodingBuilder, self).handle(tag)
                self.trace.append((tag, data))
                return data

        # taken from test_sequence (see above)
        bio = BytesIO(
            # noqa: E131
            b'\x30\x80'
                b'\x30\x0F'
                    b'\x30\x0D'
                        b'\x05\x00'
                        b'\x04\x03foo'
                        b'\x30\x80'
                            b'\x05\x00'
                        b'\x00\x00'
            b'\x00\x00'
        )
        dec = Decoder(bio)
        builder = TracingSequenceDecodingBuilder(dec)
        self.assertEqual([[[None, b'foo', [None]]]],
                         dec.read_sequence(builder))
        expected_trace = [
            # noqa: E131
            '[',
                '[',
                    '[',
                        (Tag.NULL, None),
                        (Tag.OCTETSTRING_PRIMITIVE, b'foo'),
                        '[',
                            (Tag.NULL, None),
                        ']',
                    ']',
                ']',
            ']',
        ]
        self.assertEqual(expected_trace, builder.trace)

    def _assert_sequence_of(self, value):
        self._assert_function('sequence_of', value)

    def test_sequence_of(self):
        """Encode and decode sequence-of values"""
        self._assert_sequence_of([])
        self._assert_sequence_of([b'foo', b'bar'])
        self._assert_sequence_of([b'foo', b'bar'])
        # no type checking for now (that is, we treat a sequence-of as
        # a sequence)
        self._assert_sequence_of([[], [None], [b'foo']])
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_sequence_of([])
        self.assertEqual(b'\x30\x00', bio.getvalue())

    def _assert_oid(self, oid):
        self._assert_function('oid', oid)

    def test_oid(self):
        """Encode and decode an oid"""
        self._assert_oid([0, 0])
        self._assert_oid([0, 1])
        self._assert_oid([0, 2])
        self._assert_oid([0, 39])
        self._assert_oid([0, 5, 0, 0, 0, 0, 0, 0, 1, 0, 3, 1337])
        self._assert_oid([1, 0])
        self._assert_oid([1, 1])
        self._assert_oid([1, 2])
        self._assert_oid([1, 39])
        self._assert_oid([2, 0])
        self._assert_oid([2, 1])
        self._assert_oid([2, 2])
        self._assert_oid([2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 17])
        self._assert_oid([2, 555555, 1234567890, 0, 0, 1111, 4444444444444557])
        # example from X.690 8.20
        self._assert_oid([2, 999, 3])
        bio = BytesIO()
        enc = Encoder(bio)
        enc.write_oid([2, 999, 3])
        self.assertEqual(b'\x06\x03\x88\x37\x03', bio.getvalue())


if __name__ == '__main__':
    unittest.main()
