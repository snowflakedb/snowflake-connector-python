import argparse
import logging
from probes.logging_config import initialize_logger
from probes.registry import PROBES_FUNCTIONS
import probes.login

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
    parser.add_argument("--user", required=True, help="Username")
    parser.add_argument("--private_key", required=True, help="Private key")

    # Parse arguments
    args = parser.parse_args()

    connection_params = {
        "host": args.host,
        "port": args.port,
        "role": args.role,
        "account": args.account,
        "schema": args.schema,
        "warehouse": args.warehouse,
        "user": args.user,
        "private_key": args.private_key,
    }

    for function_name, function in PROBES_FUNCTIONS.items():
        try:
            logging.info("BBB")
            logging.error(f"Running probe: {function_name}")
            function(connection_params)
        except Exception as e:
            logging.error(f"Error running probe {function_name}: {e}")


if __name__ == "__main__":
    main()
