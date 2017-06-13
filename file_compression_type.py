#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#


class FileCompressionType():
    def __init__(self):
        pass

    Types = {
        u'GZIP': {
            u'name': u'GZIP',
            u'file_extension': u'.gz',
            u'mime_type': u'application',
            u'mime_subtypes': [u'gzip', u'x-gzip'],
            u'is_supported': True,
        },
        u'DEFLATE': {
            u'name': u'DEFLATE',
            u'file_extention': u'.deflate',
            u'mime_type': u'application',
            u'mime_subtypes': [u'zlib', u'deflate'],
            u'is_supported': True,
        },
        u'RAW_DEFLATE': {
            u'name': u'RAW_DEFLATE',
            u'file_extention': u'.raw_deflate',
            u'mime_type': u'application',
            u'mime_subtypes': [u'raw_deflate'],
            u'is_supported': True,
        },
        u'BZIP2': {
            u'name': u'BZIP2',
            u'file_extention': u'.bz2',
            u'mime_type': u'application',
            u'mime_subtypes': [u'bzip2', u'x-bzip2', u'x-bz2', u'x-bzip', u'bz2'],
            u'is_supported': True,
        },
        u'LZIP': {
            u'name': u'LZIP',
            u'file_extention': u'.lz',
            u'mime_type': u'application',
            u'mime_subtypes': [u'lzip', u'x-lzip'],
            u'is_supported': False,
        },
        u'LZMA': {
            u'name': u'LZMA',
            u'file_extention': u'.lzma',
            u'mime_type': u'application',
            u'mime_subtypes': [u'lzma', u'x-lzma'],
            u'is_supported': False,
        },
        u'LZO': {
            u'name': u'LZO',
            u'file_extention': u'.lzo',
            u'mime_type': u'application',
            u'mime_subtypes': [u'lzo', u'x-lzo'],
            u'is_supported': False,
        },
        u'XZ': {
            u'name': u'XZ',
            u'file_extention': u'.xz',
            u'mime_type': u'application',
            u'mime_subtypes': [u'xz', u'x-xz'],
            u'is_supported': False,
        },
        u'COMPRESS': {
            u'name': u'COMPRESS',
            u'file_extention': u'.Z',
            u'mime_type': u'application',
            u'mime_subtypes': [u'compress', u'x-compress'],
            u'is_supported': False,
        },
        u'PARQUET': {
                u'name': u'PARQUET',
                u'file_extention': u'.parquet',
                u'mime_type': u'snowflake',
                u'mime_subtypes': [u'parquet'],
                u'is_supported': True,
        },
        u'ZSTD': {
            u'name': u'ZSTD',
            u'file_extention': u'.zst',
            u'mime_type': u'application',
            u'mime_subtypes': [u'zstd', u'x-zstd'],
            u'is_supported': True,
        },
        u'BROTLI': {
            u'name': u'BROTLI',
            u'file_extention': u'.br',
            u'mime_type': u'application',
            u'mime_subtypes': [u'br', u'x-br'],
            u'is_supported': True,
        },
        u'ORC': {
            u'name': u'ORC',
            u'file_extention': u'.orc',
            u'mime_type': u'snowflake',
            u'mime_subtypes': [u'orc'],
            u'is_supported': True,
        },
    }

    subtype_to_meta = {}

    # TODO: Snappy avro doen't need to be compressed again

    @classmethod
    def init(cls):
        for meta in cls.Types.values():
            for ms in meta[u'mime_subtypes']:
                cls.subtype_to_meta[ms] = meta

    @classmethod
    def lookupByMimeSubType(cls, mime_subtype):
        if mime_subtype.lower() in cls.subtype_to_meta:
            return cls.subtype_to_meta[mime_subtype]
        else:
            return None


# do init once
FileCompressionType.init()
