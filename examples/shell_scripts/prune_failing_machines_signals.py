"""
This script deletes signals linked to a failing machine.
"""

import argparse
import sys

from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.sql_storage import SQLStorage


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
    args = parser.parse_args()
except argparse.ArgumentError as e:
    print(e)
    parser.print_usage()
    sys.exit(2)

database = args.database
database_message = f"\tLocal storage database: {database}\n"

print(
    f"\nPruning signals for failing machines\n\n"
    f"Details:\n"
    f"{database_message}"
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
