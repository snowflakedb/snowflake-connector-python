import argparse
import logging

from probes import login, put_fetch_get  # noqa
from probes.logging_config import initialize_logger
from probes.registry import PROBES_FUNCTIONS

# Initialize logger
logger = initialize_logger(__name__)


def main():
    logger.info("Starting Python Driver Prober...")
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Python Driver Prober")
    parser.add_argument("--scope", required=True, help="Scope of probing")
    parser.add_argument("--host", required=True, help="Host")
    parser.add_argument("--port", type=int, required=True, help="Port")
    parser.add_argument("--role", required=True, help="Protocol")
    parser.add_argument("--account", required=True, help="Account")
    parser.add_argument("--schema", required=True, help="Schema")
    parser.add_argument("--warehouse", required=True, help="Warehouse")
    parser.add_argument("--database", required=True, help="Database")
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument(
        "--authenticator",
        required=True,
        help="Authenticator (e.g., KEY_PAIR_AUTHENTICATOR)",
    )
    parser.add_argument(
        "--private_key_file",
        required=True,
        help="Private key file in DER format base64-encoded and '/' -> '_', '+' -> '-' replacements",
    )

    # Parse arguments
    args = parser.parse_args()

    private_key = (
        open(args.private_key_file).read().strip().replace("_", "/").replace("-", "+")
    )

    connection_params = {
        "host": args.host,
        "port": args.port,
        "role": args.role,
        "account": args.account,
        "schema": args.schema,
        "warehouse": args.warehouse,
        "database": args.database,
        "user": args.user,
        "authenticator": args.authenticator,
        "private_key": private_key,
    }

    if args.scope not in PROBES_FUNCTIONS:
        logging.error(
            f"Invalid scope: {args.scope}. Available scopes: {list(PROBES_FUNCTIONS.keys())}"
        )
    else:
        logging.info(f"Running probe for scope: {args.scope}")
        try:
            logging.error(f"Running probe: {args.scope}")
            PROBES_FUNCTIONS[args.scope](connection_params)
        except Exception as e:
            logging.error(f"Error running probe {args.scope}: {e}")


if __name__ == "__main__":
    main()
