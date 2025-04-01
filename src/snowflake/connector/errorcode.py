#!/usr/bin/env python
from __future__ import annotations

# network
ER_FAILED_TO_CONNECT_TO_DB = 250001
ER_CONNECTION_IS_CLOSED = 250002
ER_FAILED_TO_REQUEST = 250003
ER_NOT_HTTPS_USED = 250004
ER_FAILED_TO_SERVER = 250005
ER_IDP_CONNECTION_ERROR = 250006
ER_INCORRECT_DESTINATION = 250007
ER_UNABLE_TO_OPEN_BROWSER = 250008
ER_UNABLE_TO_START_WEBSERVER = 250009
ER_INVALID_CERTIFICATE = 250011  # not used but keep here to reserve errno
ER_INVALID_BACKOFF_POLICY = 250012

# connection
ER_NO_ACCOUNT_NAME = 251001
ER_OLD_PYTHON = 251002
ER_NO_WINDOWS_SUPPORT = 251003
ER_FAILED_TO_GET_BOOTSTRAP = 251004
ER_NO_USER = 251005
ER_NO_PASSWORD = 251006
ER_INVALID_VALUE = 251007
ER_INVALID_PRIVATE_KEY = 251008
ER_NO_HOSTNAME_FOUND = 251009
ER_JWT_RETRY_EXPIRED = 251010
ER_CONNECTION_TIMEOUT = 251011
ER_RETRYABLE_CODE = 251012
ER_INVALID_WIF_SETTINGS = 251013
ER_WIF_CREDENTIALS_NOT_FOUND = 251014

# cursor
ER_FAILED_TO_REWRITE_MULTI_ROW_INSERT = 252001
ER_NO_ADDITIONAL_CHUNK = 252002
ER_NOT_POSITIVE_SIZE = 252003
ER_FAILED_PROCESSING_PYFORMAT = 252004
ER_FAILED_TO_CONVERT_ROW_TO_PYTHON_TYPE = 252005
ER_CURSOR_IS_CLOSED = 252006
ER_FAILED_TO_RENEW_SESSION = 252007
ER_UNSUPPORTED_METHOD = 252008
ER_NO_DATA_FOUND = 252009
ER_CHUNK_DOWNLOAD_FAILED = 252010
ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE = 252011
ER_FAILED_PROCESSING_QMARK = 252012

# file_transfer
ER_INVALID_STAGE_FS = 253001
ER_FAILED_TO_DOWNLOAD_FROM_STAGE = 253002
ER_FAILED_TO_UPLOAD_TO_STAGE = 253003
ER_INVALID_STAGE_LOCATION = 253004
ER_LOCAL_PATH_NOT_DIRECTORY = 253005
ER_FILE_NOT_EXISTS = 253006
ER_COMPRESSION_NOT_SUPPORTED = 253007
ER_INTERNAL_NOT_MATCH_ENCRYPT_MATERIAL = 253008
ER_FAILED_TO_CHECK_EXISTING_FILES = 253009

# ocsp
ER_OCSP_URL_INFO_MISSING = 254001
ER_OCSP_RESPONSE_UNAVAILABLE = 254002
ER_OCSP_RESPONSE_FETCH_EXCEPTION = 254003
ER_OCSP_FAILED_TO_CONNECT_CACHE_SERVER = 254004
ER_OCSP_RESPONSE_CERT_STATUS_INVALID = 254005
ER_OCSP_RESPONSE_CERT_STATUS_UNKNOWN = 254006
ER_OCSP_RESPONSE_CERT_STATUS_REVOKED = 254007
ER_OCSP_RESPONSE_STATUS_UNSUCCESSFUL = 254008
ER_OCSP_RESPONSE_ATTACHED_CERT_INVALID = 254009
ER_OCSP_RESPONSE_ATTACHED_CERT_EXPIRED = 254010
ER_OCSP_RESPONSE_INVALID_SIGNATURE = 254011
ER_OCSP_RESPONSE_INVALID_EXPIRY_INFO_MISSING = 254012
ER_OCSP_RESPONSE_EXPIRED = 254013
ER_OCSP_RESPONSE_FETCH_FAILURE = 254014
ER_OCSP_RESPONSE_LOAD_FAILURE = 254015
ER_OCSP_RESPONSE_CACHE_DOWNLOAD_FAILED = 254016
ER_OCSP_RESPONSE_CACHE_DECODE_FAILED = 254017
ER_INVALID_OCSP_RESPONSE_SSD = 254018
ER_INVALID_SSD = 254019

# converter
ER_NOT_SUPPORT_DATA_TYPE = 255001
ER_NO_PYARROW = 255002
ER_NO_ARROW_RESULT = 255003
ER_NO_PYARROW_SNOWSQL = 255004
ER_FAILED_TO_READ_ARROW_STREAM = 255005
ER_NO_NUMPY = 255006
