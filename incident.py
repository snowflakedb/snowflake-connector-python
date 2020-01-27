#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 Snowflake Computing Inc. All right reserved.
#

import logging
import platform
from datetime import datetime
from sys import exc_info
from traceback import format_exc
from uuid import uuid4

from .compat import TO_UNICODE, urlencode
from .constants import HTTP_HEADER_ACCEPT, HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_SERVICE_NAME, HTTP_HEADER_USER_AGENT
from .errors import ForbiddenError, ProgrammingError, ServiceUnavailableError
from .network import (
    ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
    CONTENT_TYPE_APPLICATION_JSON,
    PYTHON_CONNECTOR_USER_AGENT,
    REQUEST_ID,
)

logger = logging.getLogger(__name__)
URL = u'/incidents/v2/create-incident'
CLS_BLACKLIST = frozenset({ProgrammingError})

current_os_release = platform.system()
current_os_version = platform.release()


class Incident(object):

    def __init__(self,
                 job_id,
                 request_id,
                 driver,
                 driver_version,
                 error_message,
                 error_stack_trace,
                 os=current_os_release,
                 os_version=current_os_version):
        self.uuid = TO_UNICODE(uuid4())
        self.createdOn = TO_UNICODE(datetime.utcnow())[:-3]  # utcnow returns 6 ms digits, we only want 3
        self.jobId = TO_UNICODE(job_id) if job_id is not None else None
        self.requestId = TO_UNICODE(request_id) if request_id is not None else None
        self.errorMessage = TO_UNICODE(error_message)
        self.errorStackTrace = TO_UNICODE(error_stack_trace)
        self.os = TO_UNICODE(os) if os is not None else None
        self.osVersion = TO_UNICODE(os_version) if os_version is not None else None
        self.signature = TO_UNICODE(self.__generate_signature(error_message, error_stack_trace))
        self.driver = TO_UNICODE(driver)
        self.driverVersion = TO_UNICODE(driver_version)

    def to_dict(self):
        ret = {u"Tags": [{u"Name": u"driver", u"Value": self.driver},
                         {u"Name": u"version", u"Value": self.driverVersion}],
               u"Name": self.signature,
               u"UUID": self.uuid,
               u"Created_On": self.createdOn,
               u"Value": {
                   u"exceptionMessage": self.errorMessage,
                   u"exceptionStackTrace": self.errorStackTrace
               }}
        # Add optional values
        if self.os:
            ret[u"Tags"].append({u"Name": u"os", u"Value": self.os})
        if self.osVersion:
            ret[u"Tags"].append({u"Name": u"osVersion", u"Value": self.osVersion})
        if self.requestId:
            ret[u"Value"][u"requestId"] = self.requestId
        if self.jobId:
            ret[u"Value"][u"jobId"] = self.jobId
        return ret

    def __str__(self):
        return str(self.to_dict())

    def __repr__(self):
        return "Incident {id}".format(id=self.uuid)

    @staticmethod
    def __generate_signature(error_message, error_stack_trace):
        """Automatically generate signature of Incident"""
        return error_message

    @classmethod
    def from_exception(cls, exc):
        """Generate an incident from an Exception"""
        pass


class IncidentAPI(object):
    """Snowflake Incident"""

    def __init__(self, rest):
        self._rest = rest

    def report_incident(self, incident=None, job_id=None, request_id=None, session_parameters=None):
        """
        Report an incident created

        Example usage:

        from traceback import format_exc

        try:
            doing_my_thing()
        except Exception as e:
            incident = Incident(None, requestId, e.message, format_exc)
            incidentAPI.report_automatic_incident(incident)
            raise

        -- or --

        try:
            doing_my_thing()
        except Exception:
            incidentAPI.report_incident()
            raise
        """
        if incident is None:
            cls, exc, trace = exc_info()
            if cls in CLS_BLACKLIST:
                logger.warning("Ignoring blacklisted exception type: {type}".format(type=cls))
                return
            incident = Incident(job_id,
                                request_id,
                                self._rest._connection._internal_application_name,
                                self._rest._connection._internal_application_version,
                                str(exc),
                                format_exc())

        if session_parameters is None:
            session_parameters = {}
        headers = {HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
                   HTTP_HEADER_ACCEPT: ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
                   HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT}
        if HTTP_HEADER_SERVICE_NAME in session_parameters:
            headers[HTTP_HEADER_SERVICE_NAME] = \
                session_parameters[HTTP_HEADER_SERVICE_NAME]
        body = incident.to_dict()
        logger.debug(u"Going to report incident with body: {}".format(body))
        try:
            ret = self._rest.request(
                u'/incidents/v2/create-incident?' + urlencode({REQUEST_ID: uuid4()}),
                body, _include_retry_params=True)
        except (ForbiddenError, ServiceUnavailableError):
            logger.error("Unable to reach endpoint to report incident at url: '{url}' with headers='{headers}' "
                         "and body: '{body}'".format(url=URL,
                                                     headers=headers,
                                                     body=body))
            raise
        if not ret[u'success']:
            logger.warning(u"Reporting incident failed for reason: '{reason}'".format(reason=ret))
            return
        new_incident_id = ret[u'data'][u'incidentId'] if ret.get(u'data') else None
        if not new_incident_id:
            logger.debug(u"Reported incident was ignored")
        else:
            logger.info(u"Incident has been reported with new incident id: {}".format(ret[u'data'][u'incidentId']))
        return new_incident_id
