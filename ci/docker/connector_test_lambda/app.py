import logging
import sys
import xml.etree.ElementTree as ET
from glob import glob
from pathlib import Path
from subprocess import PIPE, Popen

LOGGER = logging.getLogger(__name__)
REPO_PATH = "/home/user/snowflake-connector-python"
PY_SHORT_VER = f"{sys.version_info[0]}{sys.version_info[1]}"  # 39, 310, 311, 312
ARCH = "x86"  # x86, aarch64


def run_tests():
    """Run tests using tox"""
    LOGGER.info("Running tests..")
    # Get the list of wheels; pass them to tox, one per --installpkg option.
    args = [
        "python",
        "-m",
        "tox",
        "run",
        "-e",
        f"py{PY_SHORT_VER}-lambda-ci",
        "-c",
        f"{REPO_PATH}/tox.ini",
        "--workdir",
        REPO_PATH,
    ]
    for wheel in glob(f"{REPO_PATH}/dist/*.whl"):
        args.extend(["--installpkg", wheel])

    LOGGER.info(f"Popen args: {args}")

    test_log, err = Popen(
        args,
        stdout=PIPE,
        stderr=PIPE,
    ).communicate()

    LOGGER.info(test_log)
    LOGGER.info(err)
    return test_log.decode("utf-8")


def parse_test_xml_output():
    """Parse test summary from xml report generated"""
    LOGGER.info("Parsing test result output")
    test_status = "UNKNOWN"

    default_xml_fp = f"{REPO_PATH}/junit.py{PY_SHORT_VER}-lambda-ci-dev.xml"
    files = sorted(Path(REPO_PATH).glob(f"junit.py{PY_SHORT_VER}-lambda-ci-*.xml"))
    file_path = files[0].as_posix() if files else default_xml_fp

    try:
        root = ET.parse(file_path).getroot()
        for child in root:
            failure_count = child.attrib.get("failures")
    except Exception as ex:
        LOGGER.exception(ex)
        return test_status

    if int(failure_count) == 0:
        test_status = "SUCCESS"
    else:
        test_status = "FAILURE"
    return test_status


def handler(events, context):
    """
    Lambda handler for testing Python Connector.
    """
    test_status = "UNKNOWN"
    test_result_log = "N/A"
    response = {}
    response["statusCode"] = 500
    response["testStatus"] = test_status

    # run tests
    test_result_log = run_tests()

    # parse result output
    test_status = parse_test_xml_output()

    response["statusCode"] = 200
    response["testStatus"] = test_status
    response["testLog"] = test_result_log
    return response
