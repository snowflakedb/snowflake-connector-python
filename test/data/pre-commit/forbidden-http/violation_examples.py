#!/usr/bin/env python3
"""
Example file containing various HTTP violations for testing.
This file demonstrates all the patterns the checker should detect.
"""

# SNOW001: Direct requests.request() calls
import requests

response1 = requests.request("GET", "http://example.com")

# SNOW002: Direct requests.Session() instantiation
session = requests.Session()

# SNOW003: Direct urllib3.PoolManager/ProxyManager()
import urllib3

pool = urllib3.PoolManager()
proxy = urllib3.ProxyManager("http://proxy:8080")

# SNOW004: Direct HTTP method calls
response2 = requests.get("http://example.com")
response3 = requests.post("http://example.com", data={})

# SNOW005: PoolManager().request() chained calls
response4 = urllib3.PoolManager().request("GET", "http://example.com")

# SNOW006: Direct imports of HTTP methods
from requests import get, post

result1 = get("http://example.com")
result2 = post("http://example.com", data={})

# SNOW007: Direct imports of PoolManager (runtime usage)
from urllib3 import PoolManager, ProxyManager

runtime_pool = PoolManager()
runtime_proxy = ProxyManager("http://proxy:8080")

# SNOW008: Direct imports of Session (runtime usage)
from requests import Session

runtime_session = Session()

# SNOW009: Aliased calls
import requests as req
import urllib3 as u3

aliased_response = req.get("http://example.com")
aliased_pool = u3.PoolManager()

# SNOW010: Star imports
from requests import *  # noqa: F401, F403

star_response = get("http://example.com")  # Using star-imported function

# SNOW011: Direct urllib3 API calls
direct_response = urllib3.request("GET", "http://example.com")
http_pool = urllib3.HTTPConnectionPool("example.com")

# Complex patterns
# Vendored imports
from snowflake.connector.vendored import requests as vendored_req

vendored_response = vendored_req.get("http://example.com")

# Deep attribute chains
deep_session = requests.sessions.Session()
deep_request = requests.api.request("GET", "http://example.com")

# Chained calls
chained_response = requests.Session().get("http://example.com")

# Variable aliasing
req_alias = requests
alias_response = req_alias.get("http://example.com")
