What
----
This project provides a [python-keyring](https://github.com/jaraco/keyring) [1]
backend that can be used to access the kernel keyring. In particular, we
provide

* a python-keyring backend for the kernel keyring
* a high-level interface to the kernel keyring
* a low-level module that wraps around the
  [C keyutils library](https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git) [2]

[1] https://github.com/jaraco/keyring
[2] https://git.kernel.org/pub/scm/linux/kernel/git/dhowells/keyutils.git

Security Considerations
-----------------------
The following security considerations mostly apply to the
keyutils.backend.KeyutilsKeyringBackend class (users of all other classes or
modules most likely know what they are doing). First, let's briefly outline
our keyring model. In our model, a keyring is used like this

1. Unlock the keyring
2. Store passwords and retrieve passwords
3. Lock the keyring

Before a password can be stored in or retrieved from the keyring, the keyring
has to be unlocked. Initially, the keyring is locked (that is, it is not
unlocked). Usually, the unlocking in Step 1 requires a password or some other
form of authentication.
Once the keyring is unlocked, all applications, which are able to "interact"
with the keyring/keyring daemon, have access to the stored passwords (see
Step 2). Note that these applications usually do _not_ need to authenticate
in order to set or retrieve a password.
Finally, the keyring is locked in Step 3. That is, before an application
can retrieve a password, the keyring has to be unlocked again. The locking
in Step 3 might require a password or some other form of authentication.

Next, let's briefly discuss how the keyutils.backend.KeyutilsKeyringBackend
stores a password in the kernel keyring.

```
marcus@linux:~> python3
Python 3.7.3 (default, Apr 09 2019, 05:18:21) [GCC] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from keyutils.backend import KeyutilsKeyringBackend
>>> keyring = KeyutilsKeyringBackend()
>>> keyring.set_password('service A', 'username X', 'my hidden pass')
>>>
marcus@linux:~>
```

The keyring.set\_password call basically translates to

* Check if the session keyring has a "sub" keyring that is named
  "python-keyring-keyutils". If yes, reuse it (as is). Else, create it
   (via add\_key("keyring", "python-keyring-keyutils", 23,
   KEY\_SPEC\_SESSION\_KEYRING)). In both cases, let S denote the serial number
   of the "python-keyring-keyutils" keyring.
* add\_key("user", "service A:username X", "my hidden pass", 14, S)

More precisely, the password is stored in __plaintext__ in the
"python-keyring-keyutils" keyring, which is a child of the session keyring.
The keyring and the key are created with the default permissions. Also,
if a keyring/key is reused/updated, no permissions are changed. We do not
change the permissions because there must have been a reason why a user (or
application) changed the permissions. Nevertheless, this can be considered
as a weakness.

Next, we discuss two possible attacks. For this, we only distinguish between
two types of attacks: an unprivileged process attack and a user process attack.

* In an unprivileged process attack, a process, which _has no_ permissions to
  read data from a key that is linked in the "python-keyring-keyutils" keyring,
  is able to read such a key. That is, the process has access to the plaintext
  password.
* In a user process attack, a process, which _has_ permissions to read data
  from a key that is linked in the "python-keyring-keyutils" keyring, is able
  to read such a key while the keyring is locked. That is, the process has
  access to the plaintext password while the keyring is locked. Note: here, the
  notion of locking refers to Step 3 of our keyring model.

For now, we do not care about other attacks or data integrity etc.

The KeyutilsKeyringBackend is __not__ secure against an unprivileged process
attack. However, if such an attack is possible, it most likely indicates a bug
in the kernel keyring implementation.

The KeyutilsKeyringBackend is __not__ secure against a user process attack.
This is due to the fact that the KeyutilsKeyringBackend does not provide any
explicit unlock/lock mechanism. Adding an unlock/lock mechanism is currently
on my TODO (investigate whether the "asymmetric" kernel key type could be
useful here (Idea: set_password: encrypt with the pubkey, get_password: decrypt
with the privkey, unlock: load key pair in the kernel, lock: remove key pair
(all crypto happens in the kernel)).


Remark about the keyring persistency:
The state of the keyring after a log in -> log out -> log in sequence is
configuration dependent. For instance, if this sequence is carried out via
xdm (in combination with PAM) and the /etc/pam.d/xdm file has the following
entry

```
session  optional       pam_keyinit.so revoke force
```

then a new session keyring is installed during the log in (which is revoked
during the log out). That is, the user always starts with an empty session
keyring and, hence, also with an empty/non-existent "python-keyring-keyutils"
keyring.

Remark about the return type of KeyutilsKeyringBackend.get\_password:
The keyring testsuite requires that the KeyutilsKeyringBackend.get\_password
call returns a str. Since a str is immutable, the obtained password cannot
be explicitly zapped (TODO: investigate whether setting the password to None
zeroes the memory). The KeyutilsKeyringBackend can be configured to return a
bytearray, which can be explicitly zapped.


Installation and Usage (development mode)
-----------------------------------------
Compile it and run tests:

```
marcus@linux:~/python-keyring-keyutils> mkdir out
marcus@linux:~/python-keyring-keyutils> export PYTHONPATH=out
marcus@linux:~/python-keyring-keyutils> python3 setup.py develop -d out

<Removed output (for brevity)>

marcus@linux:~/python-keyring-keyutils> pytest tests
==================================================================== test session starts ====================================================================
platform linux -- Python 3.7.3, pytest-5.2.1, py-1.8.0, pluggy-0.13.0
rootdir: /home/marcus/python-keyring-keyutils
collected 28 items                                                                                                                                          

tests/test_backend.py ...........                                                                                                                     [ 39%]
tests/test_keys.py .................                                                                                                                  [100%]

==================================================================== 28 passed in 0.42s =====================================================================
marcus@linux:~/python-keyring-keyutils>
```

Use it:

```
marcus@linux:~/python-keyring-keyutils> python3
Python 3.7.3 (default, Apr 09 2019, 05:18:21) [GCC] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from keyring.core import load_keyring
>>> keyring = load_keyring('keyutils.backend.KeyutilsKeyringBackend')
>>> keyring.set_password('service X', 'username foo', 'password bar')
>>> keyring.get_password('service X', 'username foo')
'password bar'
>>> keyring.set_password('some service', 'foobar', 'secret')
>>> keyring.delete_password('service X', 'username foo')
>>> 
marcus@linux:~/python-keyring-keyutils> keyctl show @s
Keyring
  46297307 --alswrv   1000   100  keyring: _ses
 990208180 --alswrv   1000 65534   \_ keyring: _uid.1000
 750093164 --alswrv   1000   100   \_ keyring: python-keyring-keyutils
  22790318 --alswrv   1000   100       \_ user: some service:foobar
marcus@linux:~/python-keyring-keyutils> keyctl print 22790318
secret
marcus@linux:~/python-keyring-keyutils> python3
Python 3.7.3 (default, Apr 09 2019, 05:18:21) [GCC] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from keyring.core import load_keyring
>>> keyring = load_keyring('keyutils.backend.KeyutilsKeyringBackend')
>>> keyring.get_password('some service', 'foobar')
'secret'
>>>
marcus@linux:~/python-keyring-keyutils>
```

Current Status
--------------
WIP.
