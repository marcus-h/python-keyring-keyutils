import unittest
import errno

from keyutils.keys import Key, Keyring, session_keyring


# all kernel related explanations are based on kernel
# commit 847120f859cc45e074204f4cf33c8df069306eb2


class TestKeys(unittest.TestCase):
    def setUp(self):
        # do not screw up the real session keyring
        Keyring.join_session_keyring()

    def test_key_creation(self):
        """Create a key and read its payload"""
        key = Key.create_or_update('user', 'some description', 'my payload',
                                   session_keyring)
        self.assertTrue(key.serial >= 0)
        self.assertEqual(b'my payload', key.payload())

    def test_key_update_user_key_type(self):
        """Create two keys with the same description"""
        description = 'a simple description'
        key = Key.create_or_update('user', description, 'xxx', session_keyring)
        self.assertEqual(b'xxx', key.payload())
        key2 = Key.create_or_update('user', description, 'yyy',
                                    session_keyring)
        self.assertEqual(b'yyy', key2.payload())
        # this is an implementation detail of a user key, which supports an
        # update
        self.assertEqual(b'yyy', key.payload())
        self.assertEqual(key.serial, key2.serial)

    def test_key_revoke(self):
        """Revoke a key"""
        key = Key.create_or_update('user', 'foo', 'bar', session_keyring)
        key.revoke()
        with self.assertRaises(OSError) as expected:
            key.revoke()
        # depending on /proc/sys/kernel/keys/gc_delay, the key might have
        # been subject to garbage collection, hence, check for errno.ENOKEY
        expected_errnos = (errno.EKEYREVOKED, errno.ENOKEY)
        self.assertIn(expected.exception.errno, expected_errnos)
        with self.assertRaises(OSError) as expected:
            key.payload()
        self.assertIn(expected.exception.errno, expected_errnos)

    def test_key_invalidate(self):
        """Invalidate a key"""
        key = Key.create_or_update('user', 'description', 'abcd',
                                   session_keyring)
        key.invalidate()
        with self.assertRaises(OSError) as expected:
            key.invalidate()
        self.assertEqual(errno.ENOKEY, expected.exception.errno)
        with self.assertRaises(OSError) as expected:
            key.payload()
        # Invalidating a key kicks the garbage collection. It is possible
        # that we still find the key via lookup_user_key, but we do not possess
        # the key anymore. Hence, the subsequent permission check in
        # keyctl_read_key yields -EACCES; Note: the previous key.invalidate()
        # directly yields ENOKEY because keyctl_invalidate_key passes a
        # non-zero permission to lookup_user_key => wait_for_key_construction
        # returns -ENOKEY (as in the key.payload() case) but this time it is
        # not ignored (because a non-zero permission was used)
        # Long story short: check for ENOKEY or EACCES
        expected_errnos = (errno.ENOKEY, errno.EACCES)
        with self.assertRaises(OSError) as expected:
            key.payload()
        self.assertIn(expected.exception.errno, expected_errnos)

    def test_key_create_or_update_arg_types(self):
        """Mix str and bytes arguments (also illegal ones)"""
        key = Key.create_or_update('user', b'description', 'payl\0oad',
                                   session_keyring)
        key2 = Key.create_or_update(b'user', b'description', b'payl\0oad',
                                    session_keyring)
        self.assertEqual(key.serial, key2.serial)
        self.assertEqual(b'payl\0oad', key.payload())
        with self.assertRaises(ValueError):
            Key.create_or_update('user\0', b'description', b'payload',
                                 session_keyring)
        with self.assertRaises(ValueError):
            Key.create_or_update('user', b'descri\0ption', b'payload',
                                 session_keyring)

    def test_key_create_or_update_user_type_empty_payload(self):
        """Creating a user key with an empty payload yields to EINVAL"""
        # whether an empty payload is supported or not depends on the key type
        # (hence, we cannot check this at the python level)
        with self.assertRaises(OSError) as expected:
            Key.create_or_update('user', 'foo', '', session_keyring)
        self.assertEqual(errno.EINVAL, expected.exception.errno)

    def test_key_payload_zappable(self):
        """Ensure that the object returned by Key.payload(...) can be zapped"""
        key = Key.create_or_update('user', 'descr', b'x\xdc\x00',
                                   session_keyring)
        payload = key.payload()
        self.assertEqual(b'x\xdc\x00', payload)
        payload[0] = 0
        payload[1] = 0
        self.assertEqual(b'\x00\x00\x00', payload)

    def test_keyring_add_key(self):
        """Add a key to the session keyring"""
        key = session_keyring.add_key('user', 'created via keyring', 'secret')
        self.assertTrue(key.serial >= 0)
        self.assertEqual(b'secret', key.payload())

    def test_keyring_search(self):
        """Search for an existent key"""
        session_keyring.add_key('user', 'foobar', 'xyz')
        key = session_keyring.search('user', 'foobar')
        self.assertTrue(isinstance(key, Key))
        self.assertEqual(b'xyz', key.payload())

    def test_keyring_search_non_existent(self):
        """Search for a non-existent key"""
        with self.assertRaises(OSError) as expected:
            session_keyring.search('user', 'doesnotexist')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)
        key = session_keyring.search('user', 'doesnotexist', missing_ok=True)
        self.assertIsNone(key)

    def test_keyring_search_illegal_args(self):
        """Pass illegal arguments to Keyring.search"""
        with self.assertRaises(ValueError):
            session_keyring.search('user\0', 'xxx')
        with self.assertRaises(ValueError):
            session_keyring.search('user', b'xx\0x')
        with self.assertRaises(OSError) as expected:
            session_keyring.search('non-existant type', 'xxx')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)

    def test_keyring_create(self):
        """Create sub keyrings (also check illegal args)"""
        session_keyring.create('foo')
        session_keyring.create(b'bar')
        with self.assertRaises(ValueError):
            session_keyring.create(b'foo\0bar')
        session_keyring.create(b'a').create('b').create(b'c')

    def test_keyring_create_and_search(self):
        """Create several sub keyrings and search them"""
        sub1 = session_keyring.create('sub1')
        sub2 = session_keyring.create(b'sub2')
        key1 = sub1.add_key('user', 'foo', 'abc')
        key2 = sub2.add_key('user', 'foo', 'xyz')
        self.assertEqual(b'abc', key1.payload())
        self.assertEqual(b'xyz', key2.payload())
        # search in the session keyring
        key = session_keyring.search('user', 'foo')
        self.assertEqual(b'abc', key.payload())
        # search in sub2
        key = sub2.search('user', 'foo')
        self.assertEqual(b'xyz', key.payload())
        # search for a keyring and create sub keyring
        sub = session_keyring.search('keyring', 'sub2')
        self.assertTrue(isinstance(sub, Keyring))
        subsub = sub.create('sub2sub')
        subsub.add_key('user', 'bar', 'subsub')
        key = session_keyring.search('user', 'bar')
        self.assertEqual(b'subsub', key.payload())

    def test_keyring_create_and_search_and_link(self):
        """Search for a key and link to another keyring"""
        sub1 = session_keyring.create('sub1')
        sub2 = session_keyring.create('sub2')
        sub2.add_key('user', 'foo', 'bar')
        with self.assertRaises(OSError) as expected:
            sub1.search('user', 'foo')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)
        sub2.search('user', 'foo', sub1)
        key = sub1.search('user', 'foo')
        self.assertEqual(b'bar', key.payload())

    def test_keyring_revoke(self):
        """Revoke a keyring"""
        sub = session_keyring.create('sub1')
        sub.add_key('user', 'foo', 'bar')
        key = session_keyring.search('user', 'foo')
        self.assertEqual(b'bar', key.payload())
        sub.revoke()
        with self.assertRaises(OSError) as expected:
            session_keyring.search('user', 'foo')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)

    def test_keyring_invalidate(self):
        """Invalidate a keyring"""
        sub = session_keyring.create('sub1')
        sub.add_key('user', 'foo', 'bar')
        key = session_keyring.search('user', 'foo')
        self.assertEqual(b'bar', key.payload())
        sub.invalidate()
        with self.assertRaises(OSError) as expected:
            session_keyring.search('user', 'foo')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)

    def test_keyring_join_session_keyring(self):
        session_keyring.add_key('user', 'foo', 'bar')
        sub = session_keyring.create('new sub')
        sub.add_key('user', 'bar', 'xxx')
        # sub has not the correct permissions (see the permission check in
        # find_keyring_by_name) => we join to a _new_ keyring (that has
        # neither access to foo nor bar)
        Keyring.join_session_keyring('new sub')
        with self.assertRaises(OSError) as expected:
            session_keyring.search('user', 'foo')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)
        with self.assertRaises(OSError) as expected:
            session_keyring.search('user', 'bar')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)
        # join an anonymous keyring
        Keyring.join_session_keyring()
        with self.assertRaises(OSError) as expected:
            session_keyring.search('user', 'bar')
        self.assertEqual(errno.ENOKEY, expected.exception.errno)


if __name__ == '__main__':
    unittest.main()
