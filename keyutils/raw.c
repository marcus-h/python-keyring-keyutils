#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <keyutils.h>

/*
 * Our assumption is that key_serial_t is a typedef'ed int32_t. Since there
 * is no python datatype that directly corresponds to a key_serial_t/int32_t,
 * we use a long as a substitute. That is, in the python world a key's serial
 * is just a long.
 * Why a long?
 * - a int32_t can take values from -(2^31 - 1) to 2^31 - 1 (or larger (in
 *   magnitude)) (according to the c11 standard)
 * - a long can take values from -(2^31 - 1) to 2^31 - 1 (or larger (in
 *   magnitude)) (according to the c11 standard)
 * Hence, a long seems to be a natural choice.
 * We do the dances with the assert_key_long and assert_long_key just to make
 * sure that a specific value of the one type fits into the other type. We
 * do this to make sure that a (malicious) user cannot easily sneak in some
 * overflowing value in order to operate on a "different" key.
 * Note: the macros work because both types are _signed_ integer types.
 */

/*
 * Check that our key_serial_t type assmptions are correct.
 * If our assumptions are wrong, this should result in an error/a warning
 * at compile time.
 */
static inline void compile_time_check_types() {
    key_serial_t actual;
    int32_t expected;
    (void) (&actual == &expected);
}

#define assert_key_long(key)                                                  \
do {                                                                          \
    if ((key) < LONG_MIN || (key) > LONG_MAX) {                               \
        PyErr_SetString(PyExc_ValueError, "key's serial too large for long"); \
        return NULL;                                                          \
    }                                                                         \
} while (0)

#define assert_long_key(l)                                                    \
do {                                                                          \
    if ((l) < INT32_MIN || (l) > INT32_MAX) {                                 \
        PyErr_SetString(PyExc_ValueError, "long too large for key_serial_t"); \
        return NULL;                                                          \
    }                                                                         \
} while (0)

/* Make sure that s contains no embedded nul (\0) character */
#define assert_no_embedded_nul(s)                                           \
do {                                                                        \
    size_t _len = (size_t) s ## _len;                                       \
    if ((s) != NULL && strnlen((s), _len) < _len) {                         \
        PyErr_SetString(PyExc_ValueError, #s " has embedding nul");         \
        return NULL;                                                        \
    }                                                                       \
} while (0)

PyDoc_STRVAR(raw_add_key_doc,
"add_key(type, description, payload, ringid) -> serial\n\
\n\
Add a new key or update an existing key. For the details, see\n\
man 2 add_key. Note that the plen argument, which is mentioned\n\
in the manpage, is automatically derived from the payload.\n\
type is a str/bytes/bytearray, description and playload must be a\n\
str/bytes/bytearray/None, and ringid is an int. In case of a str,\n\
its utf-8 encoding is passed to the add_key syscall.");

static PyObject *raw_add_key(PyObject *self, PyObject *args) {
    const char *type;
    Py_ssize_t type_len;
    const char *description;
    Py_ssize_t description_len;
    const char *payload;
    Py_ssize_t payload_len;
    long ringid;
    key_serial_t serial;

    if (!PyArg_ParseTuple(args, "s#z#z#l", &type, &type_len, &description,
                          &description_len, &payload, &payload_len, &ringid)) {
        return NULL;
    }
    assert_no_embedded_nul(type);
    assert_no_embedded_nul(description);
    assert_long_key(ringid);
    serial = add_key(type, description, payload, payload_len,
                     (key_serial_t) ringid);
    if (serial < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    assert_key_long(serial);
    return PyLong_FromLong((long) serial);
}

PyDoc_STRVAR(raw_keyctl_read_alloc_doc,
"keyctl_read_alloc(serial) -> bytearray\n\
\n\
Read a key's payload. For the details, see man 3 keyctl_read_alloc.\n\
serial is an int that identifies the key. Note: a bytearray instead\n\
of a bytes is used because it can be zapped by the caller (if needed).");

static PyObject *raw_keyctl_read_alloc(PyObject *self, PyObject *args) {
    long serial;
    void *payload;
    long payload_len;
    PyObject *obj;

    if (!PyArg_ParseTuple(args, "l", &serial)) {
        return NULL;
    }
    assert_long_key(serial);
    payload_len = keyctl_read_alloc((key_serial_t) serial, &payload);
    if (payload_len < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    obj = PyByteArray_FromStringAndSize(payload, payload_len);
    explicit_bzero(payload, payload_len);
    free(payload);
    return obj;
}

static PyObject *raw_keyctl_call_helper(PyObject *args,
                                        long (*func)(key_serial_t)) {
    long serial;
    long ret;

    if (!PyArg_ParseTuple(args, "l", &serial)) {
        return NULL;
    }
    assert_long_key(serial);
    ret = func((key_serial_t) serial);
    if (ret < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    Py_RETURN_NONE;
}

PyDoc_STRVAR(raw_keyctl_revoke_doc,
"keyctl_revoke(serial) -> None\n\
\n\
Revoke a key that is identified by the specified serial. serial is an\n\
int that identifies the key. For the details, see man 3 keyctl_revoke.");

static PyObject *raw_keyctl_revoke(PyObject *self, PyObject *args) {
    return raw_keyctl_call_helper(args, &keyctl_revoke);
}

PyDoc_STRVAR(raw_keyctl_invalidate_doc,
"keyctl_invalidate(serial) -> None\n\
\n\
Invalidate a key that is identified by the specified serial. serial is an\n\
int that identifies the key. For the details, see man 3 keyctl_invalidate.");

static PyObject *raw_keyctl_invalidate(PyObject *self, PyObject *args) {
    return raw_keyctl_call_helper(args, &keyctl_invalidate);
}

PyDoc_STRVAR(raw_keyring_search_doc,
"keyring_search(ringid, type, description, destringid) -> serial\n\
\n\
Search the given keyring ringid for a key of type type that matches the\n\
description. If destringid is not 0 and a key is found, it is linked\n\
to the keyring destringid. For the details, see man 3 keyctl_search.\n\
ringid is an int, type is a str/bytes/bytearray, description is a\n\
str/bytes/bytearray, and destringid is an int.");

static PyObject *raw_keyring_search(PyObject *self, PyObject *args) {
    long ringid, destringid;
    const char *type;
    Py_ssize_t type_len;
    const char *description;
    Py_ssize_t description_len;
    long serial;

    if (!PyArg_ParseTuple(args, "ls#s#l", &ringid, &type, &type_len,
                          &description, &description_len, &destringid)) {
        return NULL;
    }
    assert_long_key(ringid);
    assert_long_key(destringid);
    assert_no_embedded_nul(type);
    assert_no_embedded_nul(description);
    serial = keyctl_search((key_serial_t) ringid, type, description,
                           (key_serial_t) destringid);
    if (serial < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    /* keyctl_search returns a long (why?!) => no assertion needed */
    return PyLong_FromLong(serial);
}

PyDoc_STRVAR(raw_keyctl_join_session_keyring_doc,
"keyctl_join_session_keyring(name)\n\
\n\
Change the session keyring. For the details, see\n\
man 3 keyctl_join_session_keyring.\n\
name is is either a str/bytes/bytearray or None.");

PyObject *raw_keyctl_join_session_keyring(PyObject *self, PyObject *args) {
    const char *name;
    Py_ssize_t name_len;
    key_serial_t serial;

    if (!PyArg_ParseTuple(args, "z#", &name, &name_len)) {
        return NULL;
    }
    assert_no_embedded_nul(name);
    serial = keyctl_join_session_keyring(name);
    if (serial < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    assert_key_long(serial);
    return PyLong_FromLong((long) serial);
}

static PyMethodDef raw_methods[] = {
    {"add_key", raw_add_key, METH_VARARGS, raw_add_key_doc},
    {"keyring_search", raw_keyring_search, METH_VARARGS,
     raw_keyring_search_doc},
    {"keyctl_read_alloc", raw_keyctl_read_alloc, METH_VARARGS,
     raw_keyctl_read_alloc_doc},
    {"keyctl_revoke", raw_keyctl_revoke, METH_VARARGS, raw_keyctl_revoke_doc},
    {"keyctl_invalidate", raw_keyctl_invalidate, METH_VARARGS,
     raw_keyctl_invalidate_doc},
    {"keyctl_join_session_keyring", raw_keyctl_join_session_keyring,
     METH_VARARGS, raw_keyctl_join_session_keyring_doc},
    {NULL, NULL, 0, NULL} /* sentinel (see _add_methods_to_object) */
};

PyDoc_STRVAR(raw_doc,
"Low-level functions to access the kernel keyring.\n\
\n\
These functions are simple wrappers around the C keyutils library.");

static struct PyModuleDef raw_module = {
    PyModuleDef_HEAD_INIT,              /* m_base */
    "raw",                              /* m_name */
    raw_doc,                            /* m_doc */
    0,                                  /* m_size (we have no module state) */
    raw_methods,                        /* m_methods */
    NULL,                               /* m_slots */
    /*
     * The following functions can be called from the PyModule_Type. For
     * instance, tp_traverse calls m_traverse (if defined). The object -> type
     * association is established via the PyObject_INIT (see _PyObject_GC_New).
     */
    NULL,                               /* m_traverse */
    NULL,                               /* m_clear */
    NULL,                               /* m_free */
};

#define add_constant(m, c)                      \
do {                                            \
    if (PyModule_AddIntConstant((m), #c, c)) {  \
        return -1;                              \
    }                                           \
} while (0);

static int add_constants(PyObject *module) {
    add_constant(module, KEY_SPEC_THREAD_KEYRING);
    add_constant(module, KEY_SPEC_PROCESS_KEYRING);
    add_constant(module, KEY_SPEC_SESSION_KEYRING);
    add_constant(module, KEY_SPEC_USER_KEYRING);
    add_constant(module, KEY_SPEC_USER_SESSION_KEYRING);
    add_constant(module, KEY_SPEC_GROUP_KEYRING); /* just for completeness */
    add_constant(module, KEY_SPEC_REQKEY_AUTH_KEY);
    return 0;
}

PyMODINIT_FUNC PyInit_raw(void) {
    PyObject *module;
 
    compile_time_check_types();
    module = PyModule_Create(&raw_module);
    if (module == NULL) {
        return NULL;
    }
    if (add_constants(module)) {
        Py_DECREF(module);
        module = NULL;
    }
    return module;
}
