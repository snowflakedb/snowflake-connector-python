#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

import io
import subprocess
import zlib
from logging import getLogger

CHUNK_SIZE = 16384
MAGIC_NUMBER = 16  # magic number from requests/packages/urllib3/response.py

logger = getLogger(__name__)


def decompress_raw_data(raw_data_fd, add_bracket=True):
    """
    Decompresses raw data from file like object and return
    a byte array
    """
    obj = zlib.decompressobj(MAGIC_NUMBER + zlib.MAX_WBITS)
    writer = io.BytesIO()
    if add_bracket:
        writer.write(b'[')
    d = raw_data_fd.read(CHUNK_SIZE)
    while d:
        writer.write(obj.decompress(d))
        while obj.unused_data != b'':
            unused_data = obj.unused_data
            obj = zlib.decompressobj(MAGIC_NUMBER + zlib.MAX_WBITS)
            writer.write(obj.decompress(unused_data))
        d = raw_data_fd.read(CHUNK_SIZE)
        writer.write(obj.flush())
    if add_bracket:
        writer.write(b']')
    return writer.getvalue()


def decompress_raw_data_by_zcat(raw_data_fd, add_bracket=True):
    """
    Experiment: Decompresses raw data from file like object and return
    a byte array
    """
    writer = io.BytesIO()
    if add_bracket:
        writer.write(b'[')
    p = subprocess.Popen(["zcat"],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    writer.write(p.communicate(input=raw_data_fd.read())[0])
    if add_bracket:
        writer.write(b']')
    return writer.getvalue()


class IterStreamer(object):
    """
    File-like streaming iterator.
    """

    def __init__(self, generator):
        self.generator = generator
        self.iterator = iter(generator)
        self.leftover = ''

    def __len__(self):
        return self.generator.__len__()

    def __iter__(self):
        return self.iterator

    def next(self):
        return self.iterator.next()

    def read(self, size):
        data = self.leftover
        count = len(self.leftover)
        try:
            while count < size:
                chunk = self.next()
                data += chunk
                count += len(chunk)
        except StopIteration:
            self.leftover = ''
            return data

        if count > size:
            self.leftover = data[size:]

        return data[:size]


def decompress_raw_data_to_unicode_stream(raw_data_fd):
    """
    Decompresses a raw data in file like object and yields
    a Unicode string.
    """
    obj = zlib.decompressobj(MAGIC_NUMBER + zlib.MAX_WBITS)
    yield u'['
    d = raw_data_fd.read(CHUNK_SIZE)
    while d:
        yield obj.decompress(d).decode(u'utf-8')
        while obj.unused_data != b'':
            unused_data = obj.unused_data
            obj = zlib.decompressobj(MAGIC_NUMBER + zlib.MAX_WBITS)
            yield obj.decompress(unused_data).decode(u'utf-8')
        d = raw_data_fd.read(CHUNK_SIZE)
    yield obj.flush().decode(u'utf-8') + u']'
