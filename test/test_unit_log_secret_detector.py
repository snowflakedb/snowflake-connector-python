# !/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

from snowflake.connector.secret_detector import SecretDetector


def test_no_masking():
    test_str = "This string is innocuous"
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(test_str)
    assert not masked
    assert err_str is None
    assert masked_str == test_str


def test_mask_token():
    long_token = '_Y1ZNETTn5/qfUWj3Jedby7gipDzQs=U' \
                 'KyJH9DS=nFzzWnfZKGV+C7GopWCGD4Lj' \
                 'OLLFZKOE26LXHDt3pTi4iI1qwKuSpf/F' \
                 'mClCMBSissVsU3Ei590FP0lPQQhcSGcD' \
                 'u69ZL_1X6e9h5z62t/iY7ZkII28n2qU=' \
                 'nrBJUgPRCIbtJQkVJXIuOHjX4G5yUEKj' \
                 'ZBAx4w6=_lqtt67bIA=o7D=oUSjfywsR' \
                 'FoloNIkBPXCwFTv+1RVUHgVA2g8A9Lw5' \
                 'XdJYuI8vhg=f0bKSq7AhQ2Bh'

    token_str_w_prefix = 'Token =' + long_token
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(token_str_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'Token =****'

    id_token_str_w_prefix = 'idToken : ' + long_token
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(id_token_str_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'idToken : ****'

    session_token_w_prefix = 'sessionToken : ' + long_token
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(session_token_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'sessionToken : ****'

    master_token_w_prefix = 'masterToken : ' + long_token
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(master_token_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'masterToken : ****'

    assertion_w_prefix = 'assertion content:' + long_token
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(assertion_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'assertion content:****'


def test_token_false_positives():
    false_positive_token_str = "2020-04-30 23:06:04,069 - MainThread auth.py:397" \
                               " - write_temporary_credential() - DEBUG - no ID " \
                               "token is given when try to store temporary credential"

    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(false_positive_token_str)
    assert not masked
    assert err_str is None
    assert masked_str == false_positive_token_str


def test_password():
    random_password = 'Fh[+2J~AcqeqW%?'
    random_password_w_prefix = 'password:' + random_password
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(random_password_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'password:****'

    random_password_caps = 'PASSWORD:' + random_password
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(random_password_caps)
    assert masked
    assert err_str is None
    assert masked_str == 'PASSWORD:****'

    random_password_mix_case = 'PassWorD:' + random_password
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(random_password_mix_case)
    assert masked
    assert err_str is None
    assert masked_str == 'PassWorD:****'

    random_password_equal_sign = 'password = ' + random_password
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(random_password_equal_sign)
    assert masked
    assert err_str is None
    assert masked_str == 'password = ****'

    random_password = 'Fh[+2J~AcqeqW%?'
    random_password_w_prefix = 'pwd:' + random_password
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(random_password_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'pwd:****'


def test_token_password():
    long_token = '_Y1ZNETTn5/qfUWj3Jedby7gipDzQs=U' \
                 'KyJH9DS=nFzzWnfZKGV+C7GopWCGD4Lj' \
                 'OLLFZKOE26LXHDt3pTi4iI1qwKuSpf/F' \
                 'mClCMBSissVsU3Ei590FP0lPQQhcSGcD' \
                 'u69ZL_1X6e9h5z62t/iY7ZkII28n2qU=' \
                 'nrBJUgPRCIbtJQkVJXIuOHjX4G5yUEKj' \
                 'ZBAx4w6=_lqtt67bIA=o7D=oUSjfywsR' \
                 'FoloNIkBPXCwFTv+1RVUHgVA2g8A9Lw5' \
                 'XdJYuI8vhg=f0bKSq7AhQ2Bh'

    long_token2 = 'ktL57KJemuq4-M+Q0pdRjCIMcf1mzcr' \
                  'MwKteDS5DRE/Pb+5MzvWjDH7LFPV5b_' \
                  '/tX/yoLG3b4TuC6Q5qNzsARPPn_zs/j' \
                  'BbDOEg1-IfPpdsbwX6ETeEnhxkHIL4H' \
                  'sP-V'

    random_pwd = 'Fh[+2J~AcqeqW%?'
    random_pwd2 = random_pwd + 'vdkav13'

    test_string_w_prefix = "token=" + long_token + \
                           " random giberish " + \
                           "password:" + random_pwd
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'token=****' + \
                         " random giberish " + \
                         "password:****"

    # order reversed
    test_string_w_prefix = "password:" + random_pwd + \
                           " random giberish " + \
                           "token=" + long_token

    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'password:****' + \
                         " random giberish " + \
                         "token=****"

    # multiple tokens and password
    test_string_w_prefix = "token=" + long_token + \
                           " random giberish " + \
                           "password:" + random_pwd + \
                           " random giberish " + \
                           "idToken:" + long_token2
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == 'token=****' + \
                         " random giberish " + \
                         "password:****" + \
                         " random giberish " + \
                         "idToken:****"

    # multiple passwords
    test_string_w_prefix = "password=" + random_pwd + \
                           " random giberish " + "pwd:" \
                           + random_pwd2
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "password=" + \
                         "****" + " random giberish " \
                         + "pwd:" + "****"

    test_string_w_prefix = "password=" + random_pwd + \
                           " random giberish " + "password=" \
                           + random_pwd2 + " random giberish " + \
                           "password=" + random_pwd
    masked, masked_str, err_str = SecretDetector. \
        mask_secrets(test_string_w_prefix)
    assert masked
    assert err_str is None
    assert masked_str == "password=" + "****" + \
                         " random giberish " + "password=" \
                         + "****" + " random giberish " + \
                         "password=" + "****"
