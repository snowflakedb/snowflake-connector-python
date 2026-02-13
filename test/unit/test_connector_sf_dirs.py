from unittest import mock

from snowflake.connector.sf_dirs import SFPlatformDirs, _resolve_platform_dirs


@mock.patch("pathlib.Path.exists", side_effect=PermissionError)
def test_snowflake_home_permission_error(self):
    platform_dirs = _resolve_platform_dirs()
    assert isinstance(platform_dirs, SFPlatformDirs)
    assert platform_dirs.user_config_path.name.endswith("_snowflake")
    assert platform_dirs.user_config_path.name.startswith("tmp")
