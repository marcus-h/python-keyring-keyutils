"""A high-level interface to the kernel keyring."""

import errno

from keyutils import raw


class KeyEntity:
    """Base class for a specific key entity.

    A key entity is either a key or a keyring.
    """
    def __init__(self, serial):
        """Create a new key entity.

        The passed serial uniquely identifies the entity.
        """
        self.serial = serial

    def revoke(self):
        """Revoke the key entity."""
        raw.keyctl_revoke(self.serial)

    def invalidate(self):
        """Invalidate the key entity."""
        raw.keyctl_invalidate(self.serial)

    @staticmethod
    def _to_serial(arg):
        return getattr(arg, 'serial', arg)

    @classmethod
    def _add_key(cls, key_type, description, payload, dest_ring):
        dest_ring = cls._to_serial(dest_ring)
        serial = raw.add_key(key_type, description, payload, dest_ring)
        return cls.from_serial(serial)

    @classmethod
    def from_serial(cls, serial):
        """Construct a new instance from the specified serial."""
        return cls(serial)


class Key(KeyEntity):
    """A kernel key."""
    def payload(self):
        """Retrieve the key's payload.

        A bytearray is returned.
        """
        return raw.keyctl_read_alloc(self.serial)

    @classmethod
    def create_or_update(cls, key_type, description, payload, dest_ring):
        """Create a new key or update an existing key.

        Whether a new key is created or an existing key is updated depends
        on the key_type. The description is used to name/describe the key.
        The (key_type, description) pair is used to check if an existing key
        exists. The key's payload is specified via the payload parameter, which
        is an instance of a bytes, bytearray, or str (in case of a str, its
        utf-8 encoding is used). The created key is added to the dest_ring,
        which is an instance of the class Keyring or an int.
        """
        return cls._add_key(key_type, description, payload, dest_ring)


class Keyring(KeyEntity):
    """A kernel keyring."""
    _key_type = 'keyring'

    def add_key(self, key_type, description, payload):
        """Add a new key to this keyring.

        The key_type, description, and payload are as in Key.create_or_update.
        """
        return Key.create_or_update(key_type, description, payload,
                                    self.serial)

    def search(self, key_type, description, dest_ring=0, missing_ok=False):
        """Search for an existing key in this keyring or a subkeyring.

        The key_type and description are as in Key.create_or_update and
        represent the match criterion for the search. If no key is found,
        an OSError is raised (errno is set to ENOKEY) (if missing_ok is True,
        None is returned instead of raising an OSError). If a key is found and
        dest_ring is not 0, the key is linked into dest_ring keyring (dest_ring
        is an instance of class Keyring or an int).
        """
        dest_ring = self._to_serial(dest_ring)
        try:
            serial = raw.keyring_search(self.serial, key_type, description,
                                        dest_ring)
        except OSError as e:
            # we do _not_ treat EKEYREVOKED as missing
            if missing_ok and e.errno == errno.ENOKEY:
                return None
            raise
        if key_type == self._key_type:
            return Keyring.from_serial(serial)
        return Key.from_serial(serial)

    def create(self, description):
        """Create a new keyring.

        The description is used to name/describe the keyring.
        """
        return Keyring._add_key(self._key_type, description, None, self)

    @classmethod
    def join_session_keyring(cls, name=None):
        """Change the session keyring.

        For the details, see man 3 keyctl_join_session_keyring.
        """
        return Keyring.from_serial(raw.keyctl_join_session_keyring(name))


thread_keyring = Keyring.from_serial(raw.KEY_SPEC_THREAD_KEYRING)
process_keyring = Keyring.from_serial(raw.KEY_SPEC_PROCESS_KEYRING)
session_keyring = Keyring.from_serial(raw.KEY_SPEC_SESSION_KEYRING)
user_keyring = Keyring.from_serial(raw.KEY_SPEC_USER_KEYRING)
user_session_keyring = Keyring.from_serial(raw.KEY_SPEC_USER_SESSION_KEYRING)
# just for completeness
group_keyring = Keyring.from_serial(raw.KEY_SPEC_GROUP_KEYRING)
