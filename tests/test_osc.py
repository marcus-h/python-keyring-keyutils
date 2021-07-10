import unittest

from keyutils.keys import Keyring
from keyutils.osc import OscKernelKeyringBackend, _PasswordRetriever


class _RetrieverFactory:
    def __init__(self, password):
        self._password = password

    def __call__(self, *args, **kwargs):
        return _HardcodedPasswordRetriever(self._password, *args, **kwargs)


class _HardcodedPasswordRetriever(_PasswordRetriever):
    def __init__(self, password, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._password = password
        self.prompt_cnt = 0

    def _password_prompt(self):
        self.prompt_cnt += 1
        return self._password


class TestOsc(unittest.TestCase):
    def setUp(self):
        # do not screw up the real session keyring
        Keyring.join_session_keyring()

    def test_password_prompting_missing(self):
        """Only prompt for a password if a key is missing"""
        apiurl = 'https://example.com'
        user = 'my_user'
        factory = _RetrieverFactory('1337')
        backend = OscKernelKeyringBackend(retriever_factory=factory)
        retriever = backend.get_password(apiurl, user)
        self.assertEqual(0, retriever.prompt_cnt)
        # prompt because no password exists in the keyring
        self.assertEqual('1337', retriever())
        self.assertEqual(1, retriever.prompt_cnt)
        # since a password is present, do not prompt
        self.assertEqual('1337', retriever())
        self.assertEqual(1, retriever.prompt_cnt)
        backend.delete_password(apiurl, user)
        # prompt again because the password was deleted from the keyring
        self.assertEqual('1337', retriever())
        self.assertEqual(2, retriever.prompt_cnt)
        # since a password is present, do not prompt (as above)
        self.assertEqual('1337', retriever())
        self.assertEqual(2, retriever.prompt_cnt)

    def test_no_password_prompting_existing(self):
        """Do not prompt for a password in case of an existing key"""
        apiurl = 'https://example.net'
        user = 'foobar'
        factory = _RetrieverFactory('xxx')
        backend = OscKernelKeyringBackend(retriever_factory=factory)
        retriever = backend.get_password(apiurl, user)
        backend.set_password(apiurl, user, 'my secret')
        self.assertEqual('my secret', retriever())
        self.assertEqual(0, retriever.prompt_cnt)
        self.assertEqual('my secret', backend.get_password(apiurl, user))

    def test_retriever_consistency(self):
        """Ensure that two retrievers are consistent"""
        apiurl = 'https://localhost'
        user_foo = 'foo'
        user_bar = 'bar'
        factory = _RetrieverFactory('sEcR3t')
        backend = OscKernelKeyringBackend(retriever_factory=factory)
        retriever = backend.get_password(apiurl, user_foo)
        factory2 = _RetrieverFactory('1234')
        backend2 = OscKernelKeyringBackend(retriever_factory=factory2)
        retriever2 = backend2.get_password(apiurl, user_foo)
        # both backends and retrievers return the same password
        self.assertEqual('sEcR3t', retriever())
        self.assertEqual('sEcR3t', backend.get_password(apiurl, user_foo))
        self.assertEqual('sEcR3t', retriever2())
        self.assertEqual('sEcR3t', backend2.get_password(apiurl, user_foo))
        # obtain password for a different (non-existent) user
        retriever = backend.get_password(apiurl, user_bar)
        retriever2 = backend2.get_password(apiurl, user_bar)
        self.assertEqual('1234', retriever2())
        self.assertEqual('1234', retriever())
        self.assertEqual('1234', backend2.get_password(apiurl, user_bar))
        self.assertEqual('1234', backend.get_password(apiurl, user_bar))


if __name__ == '__main__':
    unittest.main()
