#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
"""
This sample shows how to implement a key pair authentication plugin
which reads private key from a file
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import snowflake.connector
from snowflake.connector.auth.keypair import AuthByKeyPair

PRIVATE_KEY_PASSPHRASE = (
    None  # change to your private key passphrase if it is set, else leave it None
)
PRIVATE_KEY_PATH = (
    "</path/to/private/key/file>"  # change to your own path to the private key file
)
CONNECTION_PARAMETERS = {  # change to your own snowflake credentials
    "account": "<account_name>",
    "user": "<user_name>",
    "database": "<database_name>",
    "schema": "<schema_name>",
    "protocol": "https",
    "host": "<host>",
    "port": "443",
}


class AuthByKeyPairFile(AuthByKeyPair):
    def __init__(
        self,
        private_key_path: str,  # the path to the private key file
        lifetime_in_seconds: int = 60,
    ) -> None:
        with open(private_key_path, "rb") as key:
            p_key = serialization.load_pem_private_key(
                key.read(), password=PRIVATE_KEY_PASSPHRASE, backend=default_backend()
            )
        pkb = p_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        super().__init__(private_key=pkb, lifetime_in_seconds=lifetime_in_seconds)


if __name__ == "__main__":
    # instantiate the authentication plugin
    auth_by_key_pair_file = AuthByKeyPairFile(PRIVATE_KEY_PATH)

    # pass the authentication plugin instance as the auth_class
    with snowflake.connector.connect(
        **CONNECTION_PARAMETERS, auth_class=auth_by_key_pair_file
    ) as conn:
        res = conn.cursor().execute("select 1;")
        print(res.fetchall())
