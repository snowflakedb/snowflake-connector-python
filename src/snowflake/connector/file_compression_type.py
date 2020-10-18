#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

class FileCompressionType():
    def __init__(self):
        pass

    Types = {
        'GZIP': {
            'name': 'GZIP',
            'file_extension': '.gz',
            'mime_type': 'application',
            'mime_subtypes': ['gzip', 'x-gzip'],
            'is_supported': True,
        },
        'DEFLATE': {
            'name': 'DEFLATE',
            'file_extension': '.deflate',
            'mime_type': 'application',
            'mime_subtypes': ['zlib', 'deflate'],
            'is_supported': True,
        },
        'RAW_DEFLATE': {
            'name': 'RAW_DEFLATE',
            'file_extension': '.raw_deflate',
            'mime_type': 'application',
            'mime_subtypes': ['raw_deflate'],
            'is_supported': True,
        },
        'BZIP2': {
            'name': 'BZIP2',
            'file_extension': '.bz2',
            'mime_type': 'application',
            'mime_subtypes': ['bzip2', 'x-bzip2', 'x-bz2', 'x-bzip', 'bz2'],
            'is_supported': True,
        },
        'LZIP': {
            'name': 'LZIP',
            'file_extension': '.lz',
            'mime_type': 'application',
            'mime_subtypes': ['lzip', 'x-lzip'],
            'is_supported': False,
        },
        'LZMA': {
            'name': 'LZMA',
            'file_extension': '.lzma',
            'mime_type': 'application',
            'mime_subtypes': ['lzma', 'x-lzma'],
            'is_supported': False,
        },
        'LZO': {
            'name': 'LZO',
            'file_extension': '.lzo',
            'mime_type': 'application',
            'mime_subtypes': ['lzo', 'x-lzo'],
            'is_supported': False,
        },
        'XZ': {
            'name': 'XZ',
            'file_extension': '.xz',
            'mime_type': 'application',
            'mime_subtypes': ['xz', 'x-xz'],
            'is_supported': False,
        },
        'COMPRESS': {
            'name': 'COMPRESS',
            'file_extension': '.Z',
            'mime_type': 'application',
            'mime_subtypes': ['compress', 'x-compress'],
            'is_supported': False,
        },
        'PARQUET': {
                'name': 'PARQUET',
                'file_extension': '.parquet',
                'mime_type': 'snowflake',
                'mime_subtypes': ['parquet'],
                'is_supported': True,
        },
        'ZSTD': {
            'name': 'ZSTD',
            'file_extension': '.zst',
            'mime_type': 'application',
            'mime_subtypes': ['zstd', 'x-zstd'],
            'is_supported': True,
        },
        'BROTLI': {
            'name': 'BROTLI',
            'file_extension': '.br',
            'mime_type': 'application',
            'mime_subtypes': ['br', 'x-br'],
            'is_supported': True,
        },
        'ORC': {
            'name': 'ORC',
            'file_extension': '.orc',
            'mime_type': 'snowflake',
            'mime_subtypes': ['orc'],
            'is_supported': True,
        },
    }

    subtype_to_meta = {}

    # TODO: Snappy avro doesn't need to be compressed again

    @classmethod
    def init(cls):
        for meta in cls.Types.values():
            for ms in meta['mime_subtypes']:
                cls.subtype_to_meta[ms] = meta

    @classmethod
    def lookupByMimeSubType(cls, mime_subtype):
        if mime_subtype.lower() in cls.subtype_to_meta:
            return cls.subtype_to_meta[mime_subtype]
        else:
            return None


# do init once
FileCompressionType.init()
