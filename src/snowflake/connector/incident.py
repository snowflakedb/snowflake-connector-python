#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import logging
import platform
from datetime import datetime
from sys import exc_info
from traceback import format_exc
from typing import Optional
from uuid import uuid4

from .compat import urlencode
from .constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
)
from .errors import ForbiddenError, ProgrammingError, ServiceUnavailableError
from .network import (
    ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
    CONTENT_TYPE_APPLICATION_JSON,
    PYTHON_CONNECTOR_USER_AGENT,
    REQUEST_ID,
)

logger = logging.getLogger(__name__)
URL = "/incidents/v2/create-incident"
CLS_BLACKLIST = frozenset({ProgrammingError})

current_os_release = platform.system()
current_os_version = platform.release()


class Incident(object):
    def __init__(
        self,
        job_id: Optional[str],
        request_id: Optional[str],
        driver: Optional[str],
        driver_version: Optional[str],
        error_message: Optional[str],
        error_stack_trace: Optional[str],
        os: str = current_os_release,
        os_version: str = current_os_version,
    ):
        self.uuid = str(uuid4())
        self.createdOn = str(datetime.utcnow())[
            :-3
        ]  # utcnow returns 6 ms digits, we only want 3
        self.jobId = str(job_id)
        self.requestId = str(request_id)
        self.errorMessage = str(error_message)
        self.errorStackTrace = str(error_stack_trace)
        self.os = str(os)
        self.osVersion = str(os_version)
        self.signature = str(
            self.__generate_signature(error_message, error_stack_trace)
        )
        self.driver = str(driver)
        self.driverVersion = str(driver_version)

    def to_dict(self):
        ret = {
            "Tags": [
                {"Name": "driver", "Value": self.driver},
                {"Name": "version", "Value": self.driverVersion},
            ],
            "Name": self.signature,
            "UUID": self.uuid,
            "Created_On": self.createdOn,
            "Value": {
                "exceptionMessage": self.errorMessage,
                "exceptionStackTrace": self.errorStackTrace,
            },
        }
        # Add optional values
        if self.os:
            ret["Tags"].append({"Name": "os", "Value": self.os})
        if self.osVersion:
            ret["Tags"].append({"Name": "osVersion", "Value": self.osVersion})
        if self.requestId:
            ret["Value"]["requestId"] = self.requestId
        if self.jobId:
            ret["Value"]["jobId"] = self.jobId
        return ret

    def __str__(self) -> str:
        return str(self.to_dict())

    def __repr__(self) -> str:
        return "Incident {id}".format(id=self.uuid)

    @staticmethod
    def __generate_signature(
        error_message: Optional[str], error_stack_trace: Optional[str]
    ) -> Optional[str]:
        """Automatically generates signature of Incident."""
        return error_message


class IncidentAPI(object):
    """Snowflake Incident API."""

    def __init__(self, rest):
        self._rest = rest

    def report_incident(
        self, incident=None, job_id=None, request_id=None, session_parameters=None
    ):
        """Reports an incident created.

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

        Args:
            incident: Incident to be reported, if not provided we assume that it is being raised right now
                (Default value = None).
            job_id: Job id during which the incident was observed if available (Default value = None).
            request_id: Request id during which the incident was observed if available (Default value = None).
            session_parameters: Dictionary of session parameters (Default value = None).

        Raises:
            Any error that comes from not being to reach back-end services to report incident to.
        """
        if incident is None:
            cls, exc, _ = exc_info()
            if cls in CLS_BLACKLIST:
                logger.warning(
                    "Ignoring blacklisted exception type: {type}".format(type=cls)
                )
                return
            incident = Incident(
                job_id,
                request_id,
                self._rest._connection._internal_application_name,
                self._rest._connection._internal_application_version,
                str(exc),
                format_exc(),
            )

        if session_parameters is None:
            session_parameters = {}
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if HTTP_HEADER_SERVICE_NAME in session_parameters:
            headers[HTTP_HEADER_SERVICE_NAME] = session_parameters[
                HTTP_HEADER_SERVICE_NAME
            ]
        body = incident.to_dict()
        logger.debug("Going to report incident with body: {}".format(body))
        try:
            ret = self._rest.request(
                "/incidents/v2/create-incident?" + urlencode({REQUEST_ID: uuid4()}),
                body,
                _include_retry_params=True,
            )
        except (ForbiddenError, ServiceUnavailableError):
            logger.error(
                "Unable to reach endpoint to report incident at url: '{url}' with headers='{headers}' "
                "and body: '{body}'".format(url=URL, headers=headers, body=body)
            )
            raise
        if not ret["success"]:
            logger.warning(
                "Reporting incident failed for reason: '{reason}'".format(reason=ret)
            )
            return
        new_incident_id = ret["data"]["incidentId"] if ret.get("data") else None
        if not new_incident_id:
            logger.debug("Reported incident was ignored")
        else:
            logger.info(
                "Incident has been reported with new incident id: {}".format(
                    ret["data"]["incidentId"]
                )
            )
        return new_incident_id
