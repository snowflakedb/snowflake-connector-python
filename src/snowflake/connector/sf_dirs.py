#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os
from typing import Literal

from platformdirs import PlatformDirs, PlatformDirsABC


def _resolve_platform_dirs() -> PlatformDirsABC:
    """Decide on what PlatformDirs class to use.

    In case a folder exists (which can be customized with the environmental
    variable `SNOWFLAKE_HOME`) we use that directory as all platform
    directories. If this folder does not exist we'll fall back to platformdirs
    defaults.

    This helper function was introduced to make this code testable.
    """
    platformdir_kwargs = {
        "appname": "snowflake",
        "appauthor": False,
    }
    snowflake_home = os.path.expanduser(
        os.environ.get("SNOWFLAKE_HOME", "~/.snowflake/"),
    )
    if os.path.exists(snowflake_home):
        return SFPlatformDirs(
            snowflake_home,
            **platformdir_kwargs,
        )
    else:
        # In case SNOWFLAKE_HOME does not exist we fall back to using
        # platformdirs to determine where system files should be placed. Please
        # see docs for all the directories defined in the module at
        # https://platformdirs.readthedocs.io/
        return PlatformDirs(**platformdir_kwargs)


class SFPlatformDirs(PlatformDirsABC):
    """Single folder platformdirs.

    This class introduces a PlatformDir class where everything is placed into a
    single folder. This is intended for users who prefer portability over all
    else.
    """

    def __init__(
        self,
        single_dir: str,
        appname: str | None = None,
        appauthor: str | None | Literal[False] = None,
        version: str | None = None,
        roaming: bool = False,
        multipath: bool = False,
        opinion: bool = True,
        ensure_exists: bool = False,
    ) -> None:
        super().__init__(
            appname=appname,
            appauthor=appauthor,
            version=version,
            roaming=roaming,
            multipath=multipath,
            opinion=opinion,
            ensure_exists=ensure_exists,
        )
        self.single_dir = single_dir

    @property
    def user_data_dir(self) -> str:
        """data directory tied to to the user"""
        return self.single_dir

    @property
    def site_data_dir(self) -> str:
        """data directory shared by users"""
        return self.user_data_dir

    @property
    def user_config_dir(self) -> str:
        """config directory tied to the user"""
        return self.user_data_dir

    @property
    def site_config_dir(self) -> str:
        """config directory shared by the users"""
        return self.user_data_dir

    @property
    def user_cache_dir(self) -> str:
        """cache directory tied to the user"""
        return self.user_data_dir

    @property
    def site_cache_dir(self) -> str:
        """cache directory shared by users"""
        return self.user_data_dir

    @property
    def user_state_dir(self) -> str:
        """state directory tied to the user"""
        return self.user_data_dir

    @property
    def user_log_dir(self) -> str:
        """log directory tied to the user"""
        return self.user_data_dir

    @property
    def user_documents_dir(self) -> str:
        """documents directory tied to the user"""
        return self.user_data_dir

    @property
    def user_runtime_dir(self) -> str:
        """runtime directory tied to the user"""
        return self.user_data_dir

    @property
    def user_music_dir(self) -> str:
        """music directory tied to the user"""
        return self.user_data_dir

    @property
    def user_pictures_dir(self) -> str:
        """pictures directory tied to the user"""
        return self.user_data_dir

    @property
    def user_videos_dir(self) -> str:
        """videos directory tied to the user"""
        return self.user_data_dir

    @property
    def user_downloads_dir(self) -> str:
        """downloads directory tied to the user"""
        return self.user_data_dir
