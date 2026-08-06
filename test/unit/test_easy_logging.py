import stat

import pytest

pytestmark = pytest.mark.skipolddriver

import os.path
import platform
from logging import FileHandler, getLogger
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

try:
    import tomlkit

    from snowflake.connector import EasyLoggingConfigPython
    from snowflake.connector.config_manager import CONFIG_MANAGER
    from snowflake.connector.constants import CONFIG_FILE
except ModuleNotFoundError:
    pass

import snowflake.connector

logger = getLogger("snowflake.connector")


@pytest.fixture(scope="function")
def temp_config_file(tmp_path_factory):
    config_file = tmp_path_factory.mktemp("config_file_path") / "config.toml"
    # Pre-create config file and setup correct permissions on it
    config_file.touch()
    config_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return config_file


@pytest.fixture(scope="function")
def log_directory(tmp_path_factory):
    return tmp_path_factory.mktemp("log")


@pytest.fixture(scope="module")
def nonexist_file(tmp_path_factory):
    return tmp_path_factory.mktemp("log_path") / "nonexist_file"


@pytest.fixture(scope="module")
def inaccessible_file(tmp_path_factory):
    return tmp_path_factory.mktemp("inaccessible_file")


@pytest.fixture(scope="module")
def inabsolute_file(tmp_path_factory):
    directory = tmp_path_factory.mktemp("inabsolute_file")
    return os.path.basename(directory)


def fake_connector(**kwargs) -> snowflake.connector.SnowflakeConnection:
    return snowflake.connector.connect(
        user="user",
        account="account",
        password="testpassword",
        database="TESTDB",
        warehouse="TESTWH",
        **kwargs,
    )


@pytest.fixture(scope="function")
def config_file_setup(
    request,
    temp_config_file,
    nonexist_file,
    inaccessible_file,
    inabsolute_file,
    log_directory,
):
    param = request.param
    # making different config file dir for each test to avoid race condition on modifying config.toml
    CONFIG_MANAGER.file_path = Path(temp_config_file)
    configs = {
        "nonexist_path": {"log": {"save_logs": False, "path": str(nonexist_file)}},
        "inabsolute_path": {"log": {"save_logs": False, "path": str(inabsolute_file)}},
        "inaccessible_path": {
            "log": {"save_logs": False, "path": str(inaccessible_file)}
        },
        "save_logs": {"log": {"save_logs": True, "path": str(log_directory)}},
        "no_save_logs": {"log": {"save_logs": False, "path": str(log_directory)}},
    }
    # create inaccessible path and make it inaccessible
    os.chmod(inaccessible_file, os.stat(inaccessible_file).st_mode & ~0o222)
    try:
        # create temp config file
        with open(temp_config_file, "w") as f:
            f.write(tomlkit.dumps(configs[param]))
        yield
    finally:
        # remove created dir and file, including log paths and config file paths
        CONFIG_MANAGER.file_path = CONFIG_FILE


@pytest.mark.parametrize("config_file_setup", ["nonexist_path"], indirect=True)
def test_config_file_nonexist_path(config_file_setup, nonexist_file):
    assert not os.path.exists(nonexist_file)
    EasyLoggingConfigPython()
    assert os.path.exists(nonexist_file)


@pytest.mark.parametrize("config_file_setup", ["inabsolute_path"], indirect=True)
def test_config_file_inabsolute_path(config_file_setup, inabsolute_file):
    with pytest.raises(FileNotFoundError) as e:
        EasyLoggingConfigPython()
    assert f"Log path must be an absolute file path: {str(inabsolute_file)}" in str(e)


@pytest.mark.parametrize("config_file_setup", ["inaccessible_path"], indirect=True)
@pytest.mark.skipif(
    platform.system() == "Windows", reason="Test only applicable to Windows"
)
def test_config_file_inaccessible_path(config_file_setup, inaccessible_file):
    with pytest.raises(PermissionError) as e:
        EasyLoggingConfigPython()
    assert (
        f"log path: {str(inaccessible_file)} is not accessible, please verify your config file"
        in str(e)
    )


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_save_logs(config_file_setup, log_directory):
    easy_logging = EasyLoggingConfigPython()
    easy_logging.create_log()
    logger.info("this is a test logger")
    assert os.path.exists(os.path.join(log_directory, "python-connector.log"))
    with open(os.path.join(log_directory, "python-connector.log")) as f:
        data = f.read()
        assert "this is a test logger" in data
    # reset log level
    getLogger("snowflake.connector").setLevel(10)
    getLogger("botocore").setLevel(0)
    getLogger("boto3").setLevel(0)


@pytest.mark.parametrize("config_file_setup", ["no_save_logs"], indirect=True)
def test_no_save_logs(config_file_setup, log_directory):
    easy_logging = EasyLoggingConfigPython()
    easy_logging.create_log()
    logger.info("this is a test logger")

    assert not os.path.exists(os.path.join(log_directory, "python-connector.log"))


EASY_LOGGING_LOGGERS = ("snowflake.connector", "botocore", "boto3")


@pytest.fixture(scope="function")
def reset_easy_logging():
    """Undo the process-global logging state create_log() mutates.

    create_log() attaches a shared rotating file handler to the easy-logging
    loggers and sets their levels. Without this teardown those handlers would
    leak into unrelated tests (and keep the log file open).
    """
    yield
    for logger_name in EASY_LOGGING_LOGGERS:
        log = getLogger(logger_name)
        for h in list(log.handlers):
            if isinstance(h, TimedRotatingFileHandler):
                log.removeHandler(h)
                h.close()
    getLogger("snowflake.connector").setLevel(10)
    getLogger("botocore").setLevel(0)
    getLogger("boto3").setLevel(0)


def _rotating_handlers(logger_name, log_file):
    return [
        h
        for h in getLogger(logger_name).handlers
        if isinstance(h, TimedRotatingFileHandler)
        and h.baseFilename == os.path.abspath(log_file)
    ]


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_create_log_is_idempotent_and_does_not_duplicate(
    config_file_setup, log_directory, reset_easy_logging
):
    # create_log() runs on every connection. Repeated calls must not stack
    # handlers (which would duplicate records and keep extra file handles open,
    # blocking rotation on Windows), and must not add a non-rotating root
    # FileHandler via logging.basicConfig (SNOW-3680325).
    log_file = os.path.join(log_directory, "python-connector.log")
    root_file_handlers_before = [
        h for h in getLogger().handlers if isinstance(h, FileHandler)
    ]

    easy_logging = EasyLoggingConfigPython()
    for _ in range(3):
        easy_logging.create_log()

    for logger_name in EASY_LOGGING_LOGGERS:
        rotating = _rotating_handlers(logger_name, log_file)
        assert len(rotating) == 1, (
            f"{logger_name} should have exactly one rotating handler, "
            f"got {len(rotating)}"
        )

    # The shared handler must be the same instance across loggers.
    handlers = {
        id(_rotating_handlers(name, log_file)[0]) for name in EASY_LOGGING_LOGGERS
    }
    assert len(handlers) == 1

    # basicConfig must not have added a root FileHandler.
    root_file_handlers_after = [
        h for h in getLogger().handlers if isinstance(h, FileHandler)
    ]
    assert len(root_file_handlers_after) == len(root_file_handlers_before)

    # A single emitted record must be written exactly once.
    getLogger("snowflake.connector").info("idempotent-marker")
    for h in getLogger("snowflake.connector").handlers:
        h.flush()
    with open(log_file) as f:
        assert f.read().count("idempotent-marker") == 1


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_create_log_concurrent_calls_attach_single_handler(
    config_file_setup, log_directory, reset_easy_logging
):
    # Connections may be opened concurrently from multiple threads, each calling
    # create_log(). Registration is locked so they cannot race into attaching
    # more than one handler on the same file (SNOW-3680325).
    import threading

    easy_logging = EasyLoggingConfigPython()
    log_file = os.path.join(log_directory, "python-connector.log")

    thread_count = 8
    barrier = threading.Barrier(thread_count)

    def worker():
        # Maximize contention so all threads reach create_log() together.
        barrier.wait()
        easy_logging.create_log()

    threads = [threading.Thread(target=worker) for _ in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for logger_name in EASY_LOGGING_LOGGERS:
        rotating = _rotating_handlers(logger_name, log_file)
        assert len(rotating) == 1, (
            f"{logger_name} should have exactly one rotating handler after "
            f"concurrent create_log(), got {len(rotating)}"
        )
    handlers = {
        id(_rotating_handlers(name, log_file)[0]) for name in EASY_LOGGING_LOGGERS
    }
    assert len(handlers) == 1


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_create_log_reuses_handler_for_partial_state(
    config_file_setup, log_directory, reset_easy_logging
):
    # If the shared handler is detached from some loggers but not others (e.g.
    # reset elsewhere), a subsequent create_log() must reattach that same
    # instance rather than build a second handler on the same file.
    log_file = os.path.join(log_directory, "python-connector.log")
    easy_logging = EasyLoggingConfigPython()
    easy_logging.create_log()

    original = _rotating_handlers("snowflake.connector", log_file)[0]

    # Simulate partial state: detach from one logger only.
    boto3_logger = getLogger("boto3")
    boto3_logger.removeHandler(original)
    assert original not in boto3_logger.handlers

    easy_logging.create_log()

    for logger_name in EASY_LOGGING_LOGGERS:
        rotating = _rotating_handlers(logger_name, log_file)
        assert len(rotating) == 1, (
            f"{logger_name} should have exactly one rotating handler, "
            f"got {len(rotating)}"
        )
        assert (
            rotating[0] is original
        ), f"{logger_name} should reuse the original shared handler instance"


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_create_log_reflects_changed_level_on_reuse(
    config_file_setup, log_directory, reset_easy_logging
):
    # A later connection configured with a different level must update the
    # reused handler and loggers, not stay pinned to the first level.
    import logging

    log_file = os.path.join(log_directory, "python-connector.log")
    easy_logging = EasyLoggingConfigPython()
    easy_logging.level = "INFO"
    easy_logging.create_log()

    handler = _rotating_handlers("snowflake.connector", log_file)[0]
    assert handler.level == logging.INFO

    easy_logging.level = "ERROR"
    easy_logging.create_log()

    # Same handler instance, updated level.
    assert _rotating_handlers("snowflake.connector", log_file)[0] is handler
    assert handler.level == logging.ERROR
    for logger_name in EASY_LOGGING_LOGGERS:
        assert getLogger(logger_name).level == logging.ERROR


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_create_log_masks_secrets_in_file(
    config_file_setup, log_directory, reset_easy_logging
):
    # Every record funnels through the one shared handler, whose formatter is
    # SecretDetector. A credential-shaped value must be masked in the file and
    # written exactly once.
    log_file = os.path.join(log_directory, "python-connector.log")
    easy_logging = EasyLoggingConfigPython()
    easy_logging.create_log()

    sf_logger = getLogger("snowflake.connector")
    sf_logger.info("connecting with password=SuperSecret123!")
    for h in sf_logger.handlers:
        h.flush()

    with open(log_file) as f:
        contents = f.read()
    assert "SuperSecret123!" not in contents
    assert contents.count("password=****") == 1


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_create_log_only_writes_easy_logging_loggers(
    config_file_setup, log_directory, reset_easy_logging
):
    # Pin the post-basicConfig scope: records from the easy-logging loggers reach
    # the file, but an unrelated library logger (which used to be captured via
    # the root FileHandler that basicConfig installed) does not (SNOW-3680325).
    log_file = os.path.join(log_directory, "python-connector.log")
    easy_logging = EasyLoggingConfigPython()
    easy_logging.create_log()

    getLogger("snowflake.connector").info("sf-connector-marker")
    getLogger("botocore").info("botocore-marker")
    unrelated = getLogger("some.unrelated.library")
    unrelated.setLevel(10)
    unrelated.info("unrelated-marker")

    for h in getLogger("snowflake.connector").handlers:
        h.flush()

    with open(log_file) as f:
        contents = f.read()
    assert "sf-connector-marker" in contents
    assert "botocore-marker" in contents
    assert "unrelated-marker" not in contents
