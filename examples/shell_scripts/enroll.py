"""
This script will enroll a machine.
"""

import argparse
import json
import sys
from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.sql_storage import SQLStorage
from cscapi.utils import generate_machine_id_from_key


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog, indent_increment=2, max_help_position=48, width=None):
        super().__init__(prog, indent_increment, max_help_position, width)


parser = argparse.ArgumentParser(
    description="Script to enroll a single machine.",
    formatter_class=CustomHelpFormatter,
)

try:
    parser.add_argument("--prod", action="store_true", help="Use production mode")
    parser.add_argument("--key", type=str, help="Enrollment key to use", required=True)
    parser.add_argument(
        "--human_machine_id",
        type=str,
        help="Human readable machine identifier. Will be converted in CrowdSec ID. Example: 'myMachineId'",
        required=True,
    )
    parser.add_argument("--name", type=str, help="Name of the machine", default=None)
    parser.add_argument("--overwrite", action="store_true", help="Force overwrite")
    parser.add_argument(
        "--tags",
        type=str,
        help='Json encoded list of tags. Example:\'["tag1", "tag2"]\'',
        default=None,
    )
    parser.add_argument(
        "--scenarios",
        type=str,
        help='Json encoded list of scenarios. Example:"[\\"crowdsecurity/ssh-bf\\", \\"acme/http-bf\\"]"',
        default='["crowdsecurity/ssh-bf", "acme/http-bf"]',
    )
    parser.add_argument(
        "--user_agent_prefix", type=str, help="User agent prefix", default=None
    )
    parser.add_argument(
        "--database",
        type=str,
        help="Local database name. Example: cscapi.db",
        default=None,
    )
    args = parser.parse_args()
except argparse.ArgumentError as e:
    print(e)
    parser.print_usage()
    sys.exit(2)

tags = json.loads(args.tags) if args.tags else None
scenarios = json.loads(args.scenarios) if args.scenarios else None
machine_id = generate_machine_id_from_key(args.human_machine_id)
machine_id_message = f"\tMachine ID: '{machine_id}'\n"
name_message = f" '{args.name}'" if args.name else ""
user_agent_message = (
    f"\tUser agent prefix:'{args.user_agent_prefix}'\n"
    if args.user_agent_prefix
    else ""
)
overwrite_message = "\033[1m(Force overwrite)\033[0m" if args.overwrite else ""
tags_message = f"\tTags:{args.tags}\n" if tags else ""
scenarios_message = f"\tScenarios:{args.scenarios}\n" if scenarios else ""
env_message = "\tEnv: production\n" if args.prod else "\tEnv: development\n"

database = (
    args.database
    if args.database
    else "cscapi_examples_prod.db" if args.prod else "cscapi_examples_dev.db"
)
database_message = f"\tLocal storage database: {database}\n"

print(
    f"\nEnrolling machine{name_message} with key '{args.key}' {overwrite_message}\n\n"
    f"Details:\n"
    f"{env_message}"
    f"{machine_id_message}"
    f"{scenarios_message}"
    f"{tags_message}"
    f"{user_agent_message}"
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
        scenarios=scenarios,
        prod=args.prod,
        user_agent_prefix=args.user_agent_prefix,
    ),
)

client.enroll_machines(
    machine_ids=[machine_id],
    attachment_key=args.key,
    name=args.name,
    overwrite=args.overwrite,
    tags=tags if tags else [],
)
