#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import json
import os
import re
import subprocess
from glob import glob
from io import open
from logging import getLogger

import pytest
from parameters import (CONNECTION_PARAMETERS_ADMIN)
from six import u

from snowflake.connector.compat import TO_UNICODE

logger = getLogger(__name__)


def _create_keys(tmpdir):
    sshkey_name = str(tmpdir.join('sshkey'))
    subprocess.Popen(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
         "rsa_keygen_bits:2048", "-outform", "DER",
         "-out",
         sshkey_name]).communicate()
    p1 = subprocess.Popen(
        ["openssl", "pkey", "-inform", "DER", "-in", sshkey_name,
         "-pubout", "-outform", "DER"],
        stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["openssl", "enc", "-base64", "-A"],
                          stdin=p1.stdout, stdout=subprocess.PIPE)
    out, err = p2.communicate()
    public_key = out
    return public_key, sshkey_name


def _decrypt_file_key(tmpdir, dec_key, sshkey_name):
    extracted_key_file = str(tmpdir.join('extracted_key_file'))
    logger.info(
        'decrypt key={0}, sshkey_name={1}, extracted_key_file={2}'.format(
            dec_key, sshkey_name, extracted_key_file))
    subprocess.Popen(
        ["openssl", "pkeyutl", "-decrypt", "-keyform", "DER",
         "-inkey", sshkey_name,
         "-in", dec_key, "-out", extracted_key_file],
        stdout=subprocess.PIPE).communicate()
    p1 = subprocess.Popen(["xxd", "-ps", extracted_key_file],
                          stdout=subprocess.PIPE)
    out, err = subprocess.Popen(["sed", ':a;N;$!ba;s#\\n##g'],
                                stdin=p1.stdout,
                                stdout=subprocess.PIPE).communicate()
    file_key = out.strip()
    return file_key


def _decrypt_fdn(tmpdir, fdn_files, file_key):
    decrypted_fdn_file = str(tmpdir.join('decrypted_fdn_file'))
    subprocess.Popen(
        ["openssl", "aes-256-ctr", "-e", "-nopad", "-in",
         fdn_files[0], "-out", decrypted_fdn_file, "-K",
         file_key, "-iv",
         "00000000000000000000000000000000"]).communicate()
    fdn_magic_code, _ = subprocess.Popen(
        ["xxd", "-plain", "-len", "4", decrypted_fdn_file],
        stdout=subprocess.PIPE).communicate()
    return fdn_magic_code


@pytest.mark.skipif(
    not CONNECTION_PARAMETERS_ADMIN,
    reason="The test requires the local Snowflake test environment."
)
def test_decrypt_fdn(conn_cnx, db_parameters, tmpdir):
    """
    Decript FDN file with the generated key
    """
    sf_regress_deployment_name = 'reg'
    user_reg_deployments_dir = os.path.join(
        os.path.expanduser('~'), 'sf', 'deployments',
        sf_regress_deployment_name)
    sf_deployment_root = os.getenv('SF_DEPLOYMENT_ROOT',
                                   user_reg_deployments_dir)

    sf_regress_deployment_name = os.getenv(
        'SF_REGRESS_DEPLOYMENT_NAME', sf_regress_deployment_name)

    xp_log_dirs = [
        os.path.join(sf_deployment_root, 'ExecPlatform', 'logs'),
        os.path.join(os.path.expanduser('~'), 'sf', 'deployments',
                     sf_regress_deployment_name,
                     'ExecPlatform', 'logs')]

    fdn_dir = os.getenv(
        'SF_LOCAL_INTERNAL_VOLBASE_LOCATION',
        os.path.join(user_reg_deployments_dir, 'testaccount', 'fdn'))

    public_key, sshkey_name = _create_keys(tmpdir)

    with conn_cnx() as cnx:
        cnx.cursor().execute(
            "create or replace table {0} (aa integer)".format(
                db_parameters['name']))
        try:
            c = cnx.cursor()
            c.execute("insert into {0} values(123),(456),(789)".format(
                db_parameters['name']))
            worker_files = []
            for log_dir in xp_log_dirs:
                worker_files += glob(
                    os.path.join(log_dir, 'worker*{0}*'.format(c.sfqid)))
            assert len(worker_files) >= 1, \
                'number of worker trc files in {0}'.format(xp_log_dirs)
            file_master_key_id = None
            json_content = ''
            start_plan = False
            # snip the execution plan in JSON format
            for row in open(worker_files[0], 'r', encoding='utf-8'):
                row = row.rstrip()
                if start_plan:
                    if row.startswith('['):  # timestamp
                        break
                    json_content += row
                if row.endswith('Execution plan:'):
                    start_plan = True

            assert json_content not in '', 'Execution Plan must be in JSON'
            dt = json.loads(json_content)

            file_creator_id = dt['data']['fileCreatorId']

            for rec in dt['data']['sdl']['rsos']:
                if rec['type'] == 'Insert':
                    file_master_key_id = rec['fileMasterKeyId']
                    break

            assert file_creator_id is not None, \
                'fileCreatorId in worker trc file: {0}'.format(
                    worker_files[0])

            assert file_master_key_id is not None, \
                'fileMasterKeyId in worker trc file: {0}'.format(
                    worker_files[0])

            fdn_files = glob(
                os.path.join(fdn_dir, '*{0}*.fdn'.format(
                    file_creator_id)))
            assert len(fdn_files) == 1, 'FDN file: {0}'.format(str(fdn_files))

            partial_file_name = None
            logger.info("fdn file={0}".format(fdn_files[0]))
            m = re.match(u(r'.*_(\w+_\w+_\w+_\w+)\.fdn$'),
                         os.path.basename(fdn_files[0]))
            if m:
                partial_file_name = m.group(1)
            logger.info(
                'partial_file_name=%s, '
                'file_master_key_id=%s, public_key=%s',
                partial_file_name,
                file_master_key_id,
                public_key)

            dec_key = None
            with conn_cnx(
                    account=db_parameters['sf_account'],
                    user=db_parameters['sf_user'],
                    password=db_parameters['sf_password']) as cnx_sfc:
                c_sfc = cnx_sfc.cursor()
                c_sfc.execute("select system$km_release_filekey(%s, %s, %s)", (
                    partial_file_name,
                    file_master_key_id,
                    public_key.decode('UTF-8')))
                for rec in c_sfc:
                    logger.info('km_release_filekey results = %s', rec)
                    if rec[0].endswith('enc'):
                        dec_key = rec[0]
                        break

            file_key = _decrypt_file_key(tmpdir, dec_key, sshkey_name)

            fdn_magic_code = _decrypt_fdn(tmpdir, fdn_files, file_key)
            assert u"2a46444e" in TO_UNICODE(fdn_magic_code), \
                "*FDN magic number: {0}".format(fdn_files[0])

        finally:
            cnx.cursor().execute(
                "drop table if exists {0}".format(db_parameters['name']))
