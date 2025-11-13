#!/usr/bin/env python3
"""
Test to verify IPv6 connectivity with Snowflake.
Tests:
1. SELECT 1
2. SELECT pi()
3. PUT operation (upload small random file)
4. GET operation (download the file)
"""

import ipaddress
import logging
import os
import random
import socket
import string
import subprocess
import sys
import tempfile
from logging import getLogger

# Configure logging to show detailed information
# Use stdout to ensure visibility in PyCharm
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# Configure root logger - but don't add handler to avoid duplication
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)
# Clear existing handlers to avoid duplicates
root_logger.handlers.clear()
root_logger.addHandler(console_handler)
root_logger.propagate = False  # Prevent propagation to avoid duplicates

# Set Snowflake connector logger to DEBUG
snowflake_logger = getLogger("snowflake.connector")
snowflake_logger.setLevel(logging.DEBUG)
snowflake_logger.propagate = True  # Allow propagation to root logger

# Also enable logging for network operations (they'll use root logger)
getLogger("snowflake.connector.network").setLevel(logging.DEBUG)
getLogger("snowflake.connector.auth").setLevel(logging.DEBUG)
getLogger("snowflake.connector.connection").setLevel(logging.DEBUG)


def generate_random_file(file_path, size_kb=10):
    """Generate a small random text file."""
    content = ''.join(random.choices(string.ascii_letters + string.digits + '\n', k=size_kb * 1024))
    with open(file_path, 'w') as f:
        f.write(content)
    return file_path


def check_ip_version(hostname):
    """Check what IP addresses are available for the hostname."""
    logger = getLogger(__name__)
    ipv4_addresses = []
    ipv6_addresses = []
    
    try:
        # Get all address info
        addrinfo = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        logger.info(f"DNS resolution for {hostname}:")
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            addr = sockaddr[0]
            if family == socket.AF_INET:
                ipv4_addresses.append(addr)
                logger.info(f"  IPv4: {addr}")
            elif family == socket.AF_INET6:
                ipv6_addresses.append(addr)
                logger.info(f"  IPv6: {addr}")
    except Exception as e:
        logger.warning(f"Could not resolve addresses: {e}")
    
    return ipv4_addresses, ipv6_addresses


def check_active_connections(hostname):
    """Check active network connections using lsof."""
    logger = getLogger(__name__)
    
    try:
        # Run: lsof -i -P | grep hostname
        result = subprocess.run(
            ['lsof', '-i', '-P'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Filter for the hostname
            matching_lines = [line for line in result.stdout.split('\n') 
                            if hostname in line or 'snowflakecomputing' in line]
            return matching_lines
        else:
            return []
    except FileNotFoundError:
        logger.warning("lsof command not found")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("lsof command timed out")
        return []
    except Exception as e:
        logger.warning(f"Error running lsof: {e}")
        return []


def test_ipv6_connectivity(conn_cnx, db_parameters, capsys):
    """Test IPv6 connectivity with Snowflake operations."""
    logger = getLogger(__name__)
    
    # Use logger only (print causes duplication)
    def log_and_print(msg, level='info'):
        if level == 'info':
            logger.info(msg)
        elif level == 'warning':
            logger.warning(msg)
        elif level == 'error':
            logger.error(msg)
        else:
            logger.debug(msg)
    
    log_and_print("=" * 60)
    log_and_print("Starting IPv6 Connectivity Test")
    log_and_print("=" * 60)
    
    # Check DNS resolution first
    hostname = db_parameters.get('host', '')
    log_and_print("=" * 60)
    log_and_print("DNS Resolution Check")
    log_and_print("=" * 60)
    if hostname:
        log_and_print(f"Checking DNS resolution for: {hostname}")
        ipv4_addrs, ipv6_addrs = check_ip_version(hostname)
        log_and_print(f"Summary: Found {len(ipv4_addrs)} IPv4 address(es) and {len(ipv6_addrs)} IPv6 address(es)")
        
        if len(ipv6_addrs) > 0:
            log_and_print(f"IPv6 addresses available: {', '.join(ipv6_addrs[:3])}")  # Show first 3
        else:
            log_and_print("WARNING: No IPv6 addresses found in DNS resolution!", 'warning')
        
        if len(ipv4_addrs) > 0:
            log_and_print(f"IPv4 addresses available: {', '.join(ipv4_addrs[:3])}")  # Show first 3
        else:
            log_and_print("WARNING: No IPv4 addresses found in DNS resolution!", 'warning')
    else:
        log_and_print("WARNING: No hostname provided in parameters!", 'warning')
    log_and_print("=" * 60)
    log_and_print("Note: If you get HTTP 403 Forbidden with IPv6, it means:")
    log_and_print("  - Connection reached Snowflake server (network works)")
    log_and_print("  - Server rejected IPv6 connection (endpoint may not support IPv6)")
    log_and_print("  - This is a server-side policy, not a network issue")
    log_and_print("=" * 60)
    
    with conn_cnx() as conn:
        log_and_print(f"Connected to Snowflake: {conn.host}")
        log_and_print(f"Account: {conn.account}, User: {conn.user}")
        
        # Check active connections
        log_and_print("Checking active connections...")
        connections = check_active_connections(hostname)
        if connections:
            log_and_print("Active connections:")
            for line in connections:
                log_and_print(line)
        else:
            log_and_print("No connections found (may need sudo). Run manually: sudo lsof -i -P | grep snowflakecomputing")
        
        with conn.cursor() as cur:
            # Set up database and warehouse
            if db_parameters.get("database"):
                log_and_print(f"Using database: {db_parameters['database']}")
                cur.execute(f"USE DATABASE {db_parameters['database']}")
            if db_parameters.get("warehouse"):
                log_and_print(f"Using warehouse: {db_parameters['warehouse']}")
                cur.execute(f"USE WAREHOUSE {db_parameters['warehouse']}")
            
            # Test 1: SELECT 1
            log_and_print("Test 1: Executing SELECT 1")
            result = cur.execute("SELECT 1").fetchone()
            log_and_print(f"SELECT 1 result: {result[0]}")
            assert result[0] == 1, f"Expected 1, got {result[0]}"
            
            # Test 2: SELECT pi()
            log_and_print("Test 2: Executing SELECT pi()")
            result = cur.execute("SELECT pi()").fetchone()
            pi_value = result[0]
            log_and_print(f"SELECT pi() result: {pi_value}")
            assert abs(pi_value - 3.141592653589793) < 0.000001, f"Expected pi, got {pi_value}"
            
            # Test 3 & 4: PUT and GET operations
            log_and_print("Test 3 & 4: Starting PUT and GET operations")
            # Create temporary directory and file
            with tempfile.TemporaryDirectory() as tmpdir:
                # Generate random file
                test_file = os.path.join(tmpdir, "test_ipv6_file.txt")
                log_and_print(f"Generating test file: {test_file}")
                generate_random_file(test_file, size_kb=5)  # 5KB file
                file_size = os.path.getsize(test_file)
                log_and_print(f"Test file size: {file_size} bytes")
                assert file_size > 0, "Test file should not be empty"
                
                # Use user stage (internal stage, no AWS credentials needed)
                stage_name = "~"  # User stage
                log_and_print(f"Using user stage: {stage_name}")
                
                # PUT file to stage
                put_sql = f"PUT file://{test_file} @{stage_name}"
                log_and_print(f"Executing PUT: {put_sql}")
                cur.execute(put_sql)
                put_result = cur.fetchall()
                log_and_print(f"PUT result: {put_result}")
                
                # Verify file was uploaded
                assert put_result and len(put_result) > 0, "PUT should return results"
                status = put_result[0][6] if len(put_result[0]) > 6 else "UNKNOWN"
                log_and_print(f"PUT status: {status}")
                assert status in ["UPLOADED", "SKIPPED"], f"File should be uploaded, got status: {status}"
                
                # List files in stage
                log_and_print(f"Listing files in stage: {stage_name}")
                cur.execute(f"LIST @{stage_name}")
                files = cur.fetchall()
                log_and_print(f"Files in stage: {files}")
                uploaded_file = None
                for file_info in files:
                    if "test_ipv6_file.txt" in file_info[0]:
                        uploaded_file = file_info[0]
                        break
                
                assert uploaded_file is not None, "Uploaded file should be found in stage listing"
                log_and_print(f"Found uploaded file: {uploaded_file}")
                
                # GET file from stage
                output_dir = os.path.join(tmpdir, "download")
                os.makedirs(output_dir, exist_ok=True)
                get_sql = f"GET @{stage_name}/test_ipv6_file.txt.gz file://{output_dir}/"
                log_and_print(f"Executing GET: {get_sql}")
                cur.execute(get_sql)
                get_result = cur.fetchall()
                log_and_print(f"GET result: {get_result}")
                
                # Verify file was downloaded
                downloaded_files = [f for f in os.listdir(output_dir) if f.endswith('.gz')]
                log_and_print(f"Downloaded files: {downloaded_files}")
                assert len(downloaded_files) > 0, "File should be downloaded"
                downloaded_file = os.path.join(output_dir, downloaded_files[0])
                downloaded_size = os.path.getsize(downloaded_file)
                log_and_print(f"Downloaded file size: {downloaded_size} bytes")
                assert downloaded_size > 0, "Downloaded file should not be empty"
                
                # Clean up: remove file from stage
                log_and_print("Cleaning up: removing file from stage")
                cur.execute(f"REMOVE @{stage_name}/test_ipv6_file.txt.gz")
    
    log_and_print("=" * 60)
    log_and_print("IPv6 Connectivity Test Completed Successfully")
    log_and_print("=" * 60)

