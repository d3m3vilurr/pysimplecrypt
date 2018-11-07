import sys
from setuptools import setup

install_requires = []

if sys.hexversion < 0x03040000:
    install_requires.append('enum34')

classifiers = [
    'Development Status :: 5 - Production/Stable',
    'License :: OSI Approved :: BSD License',
    'Operating System :: OS Independent',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
]

setup(
    name='simplecrypt',
    version='1.0',
    description='Pure python port of QT SimpleCrypt',
    long_description=open('README.md').read(),
    license='BSD',
    author='Sunguk Lee',
    author_email='d3m3vilurr@gmail.com',
    install_requires=install_requires,
    py_modules=['simplecrypt'],
    classifiers=classifiers,
)
