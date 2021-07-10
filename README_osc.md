The `keyutils.osc` module provides a
[python-keyring](https://github.com/jaraco/keyring) [1] backend
that can be used by
[osc](https://github.com/openSUSE/osc) for managing the credentials
in the kernel keyring.


Security Considerations
-----------------------
Since the `keyutils.osc.OscKernelKeyringBackend` class is a subclass of the
`keyutils.keys.KeyutilsKeyringBackend` class, all security considerations
from the
[README.md](https://github.com/marcus-h/python-keyring-keyutils/blob/master/README.md) [3]
also apply. Additionally, it is important to note that osc itself
uses a cookie that can be used for authentication. That is, even if
no/arbitrary credentials are stored in the kernel keyring, it is possible to
authenticate via the cookie (the cookie is stored in the
`~/.osc\_cookiejar` file).


Usage
-----
After the installation of this backend, osc can be instructed to use it
for storing the credentials for a specific apiurl in the kernel keyring.
When configuring the credentials for a new apiurl, osc offers several
methods for storing the credentials. For instance,

```
marcus@linux:~> osc -A https://api.opensuse.org ls home:Marcus_H

the apiurl 'https://api.opensuse.org' does not exist in the config file. Please enter
your credentials for this apiurl.

Username: Marcus_H
Password:
1) backend KeyutilsKeyringBackend (Backend provided by python-keyring)
2) chainer ChainerBackend (Backend provided by python-keyring)
3) fail Keyring (Backend provided by python-keyring)
4) osc OscKernelKeyringBackend (Backend provided by python-keyring)
5) Config file credentials manager (Store the credentials in the config file (plain text))
6) Obfuscated Config file credentials manager (Store the credentials in the config file (obfuscated))
7) Transient password store (Do not store the password and always ask for the password)
Select credentials manager: 4

<command output omitted>

marcus@linux:~>
```

That is, the `OscKernelKeyringBackend` is selected by choosing option 4.

Alternatively, osc can also be configured to use the `OscKernelKeyringBackend`
for an existing apiurl. In this case, the credentials are removed from the
existing backend and are stored in the kernel keyring. For instance,

```
marcus@linux:~> osc config https://api.opensuse.org --change-password
Password:
1) backend KeyutilsKeyringBackend (Backend provided by python-keyring)
2) chainer ChainerBackend (Backend provided by python-keyring)
3) fail Keyring (Backend provided by python-keyring)
4) osc OscKernelKeyringBackend (Backend provided by python-keyring)
5) Config file credentials manager (Store the credentials in the config file (plain text))
6) Obfuscated Config file credentials manager (Store the credentials in the config file (obfuscated))
7) Transient password store (Do not store the password and always ask for the password)
Select credentials manager: 4
Password has been changed.
marcus@linux:~>
```

As above, the `OscKernelKeyringBackend` is selected by choosing option 4.

Note that the password has to be entered again. Actually, in order to
simply change the password store (without entering the password again),
it should be sufficient to run
`osc config https://api.opensuse.org pass --select-password-store` but
there is currently a bug in osc.

By default (and there is currently no way to configure this), the credentials
are stored in the `osc_credentials` keyring, which is a "sub" keyring of the
session keyring. For instance, the session keyring can be inspected via the
keyctl tool, which is part of the
[C keyutils library](https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git) [4],
as follows

```
marcus@linux:~> keyctl show @s
Keyring
 984469378 --alswrv   1000   100  keyring: _ses
 847671581 --alswrv   1000 65534   \_ keyring: _uid.1000
 228550152 --alswrv   1000   100   \_ keyring: osc_credentials
 689394544 --alswrv   1000   100       \_ user: api.opensuse.org:Marcus_H
marcus@linux:~>
```

The password of the user Marcus\_H for the api.opensuse.org host can be
retrieved via

```
marcus@linux:~> keyctl print 689394544
mySecretPassword
marcus@linux:~>
```

Moreover, it is also possible to "remove" the password from the keyring.
Afterwards, a subsequent osc invocation asks for the password and stores
it in the `osc_credentials` keyring again.

```
marcus@linux:~> keyctl unlink 689394544
1 links removed
marcus@linux:~> keyctl show @s
Keyring
 984469378 --alswrv   1000   100  keyring: _ses
 847671581 --alswrv   1000 65534   \_ keyring: _uid.1000
 228550152 --alswrv   1000   100   \_ keyring: osc_credentials
marcus@linux:~> osc ls home:Marcus_H
Password required for user Marcus_H (apiurl: api.opensuse.org)
Password:

<command output omitted>

marcus@linux:~> keyctl show @s
Keyring
 984469378 --alswrv   1000   100  keyring: _ses
 847671581 --alswrv   1000 65534   \_ keyring: _uid.1000
 228550152 --alswrv   1000   100   \_ keyring: osc_credentials
 203276964 --alswrv   1000   100       \_ user: api.opensuse.org:Marcus_H
marcus@linux:~>
```

Note: the "persistence" of the session keyring is configuration dependent.
For instance, xdm can be configured to create a new session keyring during
the log in, which is revoked during the log out (see also the
[README.md](https://github.com/marcus-h/python-keyring-keyutils/blob/master/README.md) [3]
file).


References
----------
[1] https://github.com/jaraco/keyring
[2] https://github.com/openSUSE/osc
[3] https://github.com/marcus-h/python-keyring-keyutils/blob/master/README.md
[4] https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git
