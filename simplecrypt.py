# -*- coding: utf-8 -*-
# Copyright (c) 2016, Sunguk Lee
# Original C++ Copyright (c) 2011, Andre Somers
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Rathenau Instituut, Andre Somers nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE # DISCLAIMED. IN NO EVENT SHALL ANDRE SOMERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR #######; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from enum import Enum, IntEnum
import base64
from PyQt5.QtCore import QByteArray, QDateTime, QCryptographicHash, \
                         QDataStream, QIODevice, \
                         qsrand, qrand, qCompress, qChecksum

__all__ = ['CompressionMode', 'IntegrityProtectionMode', 'Error', 'CryptoFlag',
           'SimpleCrypt']


class CompressionMode(Enum):
    CompressionAuto = 0
    CompressionAlways = 1
    CompressionNever = 2


class IntegrityProtectionMode(Enum):
    ProtectionNone = 0
    ProtectionChecksum = 1
    ProtectionHash = 2


class Error(IntEnum):
    ErrorNoError = 0
    ErrorNoKeySet = 1
    ErrorUnknownVersion = 2
    ErrorIntegrityFailed = 3


class CryptoFlag(IntEnum):
    CryptoFlagNone = 0
    CryptoFlagCompression = 0x01
    CryptoFlagChecksum = 0x02
    CryptoFlagHash = 0x04


class SimpleCrypt(object):

    def __init__(self, key=0):
        self._key = key
        self._compression_mode = CompressionMode.CompressionAuto
        self._protection_mode = IntegrityProtectionMode.ProtectionChecksum
        self.last_error = Error.ErrorNoError
        qsrand(QDateTime.currentMSecsSinceEpoch() & 0xFFFF)
        self._key_parts = []
        if key:
            self.split_key()

    def set_key(self, key):
        self._key = key
        self.split_key()

    def split_key(self):
        self._key_parts = []
        for x in range(8):
            part = self._key & 0xffffffffffffffff
            for y in range(x, 0, -1):
                part >>= 8
            part &= 0xff
            self._key_parts.append(part)

    def encrypt_to_bytes(self, text):
        if type(text) == str:
            text = text.encode('utf-8')
        if type(text) != bytes:
            return b''

        if not len(self._key_parts):
            # no key set
            self.last_error = 1
            return b''
        ba = text
        flags = CryptoFlag.CryptoFlagNone.value

        if self._compression_mode == CompressionMode.CompressionAlways:
            # maximum compression
            ba = qCompress(QByteArray(ba), 9).data()
            flags |= CryptoFlag.CryptoFlagCompression.value
        elif self._compression_mode == CompressionMode.CompressionAuto:
            compressed = qCompress(QByteArray(ba), 9)
            if compressed.count() < len(ba):
                ba = compressed.data()
                flags != CryptoFlag.CryptoFlagCompression.value

        integrity_protection = QByteArray()
        if self._protection_mode == IntegrityProtectionMode.ProtectionChecksum:
            flags |= CryptoFlag.CryptoFlagChecksum.value
            s = QDataStream(integrity_protection, QIODevice.WriteOnly)
            s.writeUInt16(qChecksum(ba))
        elif self._protection_mode == IntegrityProtectionMode.ProtectionHash:
            flags |= CryptoFlag.CryptoFlagHash.value
            qhash = QCryptographicHash(QCryptographicHash.Sha1)
            qhash.addData(QByteArray(ba))
            integrity_protection += qhash.result()
        integrity_protection = integrity_protection.data()

        random_char = chr(qrand() & 0xff)
        ba = random_char.encode('latin1') + integrity_protection + ba

        pos = 0
        last = 0

        cnt = len(ba)
        while pos < cnt:
            curr = ba[pos]
            new = curr ^ self._key_parts[pos % 8] ^ last
            ba = ba[:pos] + chr(new).encode('latin1') + ba[pos + 1:]
            last = new
            pos += 1
        result = [
            # version for future updates to algorithm
            chr(0x3).encode('latin1'),
            # encryption flags
            chr(flags).encode('latin1'),
        ]

        self.last_error = Error.ErrorNoError
        return b''.join(result) + ba

    def encrypt_to_string(self, text):
        cypher = self.encrypt_to_bytes(text)
        return base64.b64encode(cypher)

    def decrypt_to_string(self, cypher):
        plain = self.decrypt_to_bytes(cypher)
        return plain.decode('utf-8')

    def decrypt_to_bytes(self, cypher):
        if type(cypher) == str:
            cypher = base64.b64decode(cypher.encode('latin1'))
        if type(cypher) != bytes:
            return b''

        if not len(self._key_parts):
            # no key set
            self.last_error = 1
            return b''

        if len(cypher) < 3:
            return b''

        ba = cypher
        version = ba[0]

        # we only work with version 3
        if version != 3:
            self.last_error = Error.ErrorUnknownVersion
            return b''

        flags = ba[1]

        ba = ba[2:]
        pos = 0
        cnt = len(ba)
        last = 0

        while pos < cnt:
            curr = ba[pos]
            new = curr ^ last ^ self._key_parts[pos % 8]
            ba = ba[:pos] + chr(new).encode('latin1') + ba[pos + 1:]
            last = curr
            pos += 1

        # chop off the random number at the start
        ba = ba[1:]

        integrity_ok = True

        if flags & CryptoFlag.CryptoFlagChecksum:
            if len(ba) < 2:
                self.last_error = Error.ErrorIntegrityFailed
                return b''
            _ = QByteArray(ba)
            s = QDataStream(_, QIODevice.ReadOnly)
            stored_checksum = s.readUInt16()
            ba = ba[2:]
            integrity_ok = qChecksum(ba) == stored_checksum
        elif flags & CryptoFlag.CryptoFlagHash:
            if len(ba) < 20:
                self.lastError = Error.ErrorIntegrityFailed
                return b''
            stored_hash = be[:20]
            ba = ba[20:]
            qhash = QCryptographicHash(QCryptographicHash.Sha1)
            qhash.addData(QByteArray(ba));
            integrity_ok = (qhash.result() == stored_hash);

        if not integrity_ok:
            self.last_error = Error.ErrorIntegrityFailed
            return b''

        if flags & CryptoFlag.CryptoFlagCompression:
            ba = qUncompress(QByteArray(ba)).data();

        self.last_error = Error.ErrorNoError
        return ba

if __name__ == '__main__':
    crypto = SimpleCrypt(0x0123456789abcdef)
    e = crypto.encrypt_to_bytes('abcd')
    assert(crypto.decrypt_to_string(e) == 'abcd')
    assert(crypto.decrypt_to_string('AwLohkauq43K') == 'abcd')
