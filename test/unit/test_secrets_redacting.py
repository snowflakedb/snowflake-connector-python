from unittest.mock import MagicMock, Mock

import pytest

from snowflake.connector.network import SnowflakeRestful


@pytest.mark.parametrize('field', ['TOKEN', 'PASSWORD'])
def test_secrets_are_hidden(caplog, field):
    connection = MagicMock()
    connection.errorhandler = Mock(return_value=None)
    rest = SnowflakeRestful(
        host="testaccount.snowflakecomputing.com", port=443, connection=connection
    )
    rest._request_exec = MagicMock(return_value=None)

    default_parameters = {
        "method": "POST",
        "full_url": "https://testaccount.snowflakecomputing.com/",
        "headers": {},
        "data": '{{"data": {{"{field}": "secret"}}}}'.format(field),
    }
    rest.fetch(timeout=10, **default_parameters)

    logs = [msg for msg in caplog.messages if field in msg]
    secrets = [msg for msg in logs if 'secret' in msg]
    assert logs  # at least one log line is caught
    assert not secrets
