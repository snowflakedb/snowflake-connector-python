#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from datetime import datetime
from logging import getLogger
from .constants import (
        PARAMETER_TIMEZONE
)

import pytz

try:
    import tzlocal
except ImportError:
    tzlocal = None

logger = getLogger(__name__)


class ArrowConverterContext(object):
    def __init__(self, session_parameters={}):
        self._timezone = None if PARAMETER_TIMEZONE not in session_parameters else session_parameters[PARAMETER_TIMEZONE]

    @property
    def timezone(self):
        return self._timezone

    @timezone.setter
    def timezone(self, tz):
        self._timezone = tz

    def get_session_tz(self):
        """ Get the session timezone or use the local computer's timezone. """
        try:
            tz = 'UTC' if not self.timezone else self.timezone
            return pytz.timezone(tz)
        except pytz.exceptions.UnknownTimeZoneError:
            logger.warning('converting to tzinfo failed')
            if tzlocal is not None:
                return tzlocal.get_localzone()
            else:
                try:
                    return datetime.timezone.utc
                except AttributeError:
                    return pytz.timezone('UTC')
