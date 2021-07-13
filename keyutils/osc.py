"""A python-keyring backend tailored for the osc [1] application.

The OscKernelKeyringBackend is a special python-keyring backend that can be
used by osc [1]. In particular, its get_password method returns a callable
instead of None in case of a non-existing password for a service, username
pair. When calling this callable, it either
- returns the password, which was stored in the meantime in the kernel
  keyring, OR
- prompts for the password and stores it in the kernel keyring.

[1] https://github.com/openSUSE/osc
"""

import getpass

from keyutils.backend import KeyutilsKeyringBackend


class OscKernelKeyringBackend(KeyutilsKeyringBackend):
    """Manage osc's credentials in the kernel keyring."""
    def __init__(self, keyring_name='osc_credentials', retriever_factory=None,
                 **kwargs):
        super().__init__(keyring_name=keyring_name, **kwargs)
        if retriever_factory is None:
            retriever_factory = _PasswordRetriever
        self._retriever_factory = retriever_factory

    def get_password(self, service, username, defer=True):
        password = super().get_password(service, username)
        if password is None and defer:
            return self._retriever_factory(self, service, username)
        return password


class _PasswordRetriever:
    def __init__(self, backend, service, username):
        self._backend = backend
        self._service = service
        self._username = username

    def _password_prompt(self):
        print("Password required for user {} (apiurl: {})".format(
            self._username, self._service
        ))
        return getpass.getpass('Password: ')

    def __call__(self):
        password = self._backend.get_password(self._service, self._username,
                                              defer=False)
        if password is not None:
            return password
        password = self._password_prompt()
        self._backend.set_password(self._service, self._username, password)
        return password
