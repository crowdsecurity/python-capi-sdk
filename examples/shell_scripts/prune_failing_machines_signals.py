"""
This script deletes signals linked to a failing machine.
"""

import argparse
import sys
import logging

from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.sql_storage import SQLStorage

logger = logging.getLogger("capi-py-sdk")
logger.setLevel(logging.DEBUG)  # Change this to the level you want
console_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog, indent_increment=2, max_help_position=48, width=None):
        super().__init__(prog, indent_increment, max_help_position, width)


parser = argparse.ArgumentParser(
    description="Script to prune failing machines signals.",
    formatter_class=CustomHelpFormatter,
)

try:
    parser.add_argument(
        "--database",
        type=str,
        help="Local database name. Example: cscapi.db",
        required=True,
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        help="Batch size for pruning signals. Example: 1000",
        default=1000,
    )
    args = parser.parse_args()
except argparse.ArgumentError as e:
    print(e)
    parser.print_usage()
    sys.exit(2)

database = args.database
database_message = f"\tLocal storage database: {database}\n"
batch_size_message = f"\tBatch size: {args.batch_size}\n"

print(
    f"\nPruning signals for failing machines\n\n"
    f"Details:\n"
    f"{database_message}"
    f"{batch_size_message}"
    f"\n\n"
)

confirmation = input("Do you want to proceed? (Y/n): ")
if confirmation.lower() == "n":
    print("Operation cancelled by the user.")
    sys.exit()

client = CAPIClient(
    storage=SQLStorage(connection_string=f"sqlite:///{database}"),
    config=CAPIClientConfig(
        scenarios=[],
    ),
)


client.prune_failing_machines_signals()
