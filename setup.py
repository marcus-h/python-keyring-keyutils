from setuptools import setup
from setuptools.extension import Extension


setup(
    name='keyring-keyutils',
    version='0.1',
    author='Marcus Hüwe',
    author_email='suse-tux@gmx.de',
    description='A python-keyring backend for the kernel keyring.',
    packages=['keyutils'],
    ext_modules=[
        Extension('keyutils.raw', ['keyutils/raw.c'], libraries=['keyutils'],
                  extra_compile_args=['-Werror'])
    ],
    entry_points={
        'keyring.backends': [
            'Keyutils/KernelKeyring = keyutils.backend:KeyutilsKeyringBackend'
        ]
    }
)
