"""
This script will send a simple signal.
"""

import argparse
import json
import sys
from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.sql_storage import SQLStorage
from cscapi.utils import create_signal
from cscapi.utils import generate_machine_id_from_key


class CustomHelpFormatter(argparse.HelpFormatter):
    def __init__(self, prog, indent_increment=2, max_help_position=48, width=None):
        super().__init__(prog, indent_increment, max_help_position, width)


parser = argparse.ArgumentParser(
    description="Script to send a simple signal.",
    formatter_class=CustomHelpFormatter,
)

try:
    parser.add_argument("--prod", action="store_true", help="Use production mode")
    parser.add_argument(
        "--human_machine_id",
        type=str,
        help="Human readable machine identifier. Will be converted in CrowdSec ID. Example: 'myMachineId'",
        required=True,
    )
    parser.add_argument("--ip", type=str, help="Attacker IP", required=True)
    parser.add_argument(
        "--created_at",
        type=str,
        help="Signal's creation date. Example:'2024-01-26 10:20:46+0000'",
        default="2024-01-26 10:20:46+0000",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Signal's scenario. Example: 'crowdsecurity/ssh-bf'",
        required=True,
    )
    parser.add_argument(
        "--machine_scenarios",
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
    parser.add_argument(
        "--context",
        type=str,
        help='Json encoded context. Example:"[{\\"key\\":\\"key1\\", '
        '\\"value\\":\\"value1\\"}, {\\"key\\":\\"key2\\", \\"value\\":\\"value2\\"}]"',
        default=None,
    )
    args = parser.parse_args()
except argparse.ArgumentError as e:
    print(e)
    parser.print_usage()
    sys.exit(2)
machine_id = generate_machine_id_from_key(args.human_machine_id)
machine_id_message = f"machine ID: '{machine_id}'"
ip_message = f"\tAttacker IP: '{args.ip}'\n"
created_at_message = f"\tCreated at: '{args.created_at}'\n"
scenario_message = f"\tScenario: '{args.scenario}'\n"
context_message = f"\tContext:{args.context}\n" if args.context else ""
machine_scenarios = (
    json.loads(args.machine_scenarios) if args.machine_scenarios else None
)
context = json.loads(args.context) if args.context else None
user_agent_message = (
    f"\tUser agent prefix:'{args.user_agent_prefix}'\n"
    if args.user_agent_prefix
    else ""
)
machine_scenarios_message = (
    f"\tMachine's scenarios:{args.machine_scenarios}\n" if machine_scenarios else ""
)
env_message = "\tEnv: production\n" if args.prod else "\tEnv: development\n"

database = (
    args.database
    if args.database
    else "cscapi_examples_prod.db" if args.prod else "cscapi_examples_dev.db"
)
database_message = f"\tLocal storage database: {database}\n"

print(
    f"\nSending signal for {machine_id_message}\n\n"
    f"Details:\n"
    f"{env_message}"
    f"{ip_message}"
    f"{scenario_message}"
    f"{created_at_message}"
    f"{context_message}"
    f"{machine_scenarios_message}"
    f"{database_message}"
    f"{user_agent_message}"
    f"\n\n"
)

confirmation = input("Do you want to proceed? (Y/n): ")
if confirmation.lower() == "n":
    print("Operation cancelled by the user.")
    sys.exit()

client = CAPIClient(
    storage=SQLStorage(connection_string=f"sqlite:///{database}"),
    config=CAPIClientConfig(
        scenarios=machine_scenarios,
        prod=args.prod,
        user_agent_prefix=args.user_agent_prefix,
    ),
)

signals = [
    create_signal(
        attacker_ip=args.ip,
        scenario=args.scenario,
        created_at=args.created_at,
        machine_id=machine_id,
        context=context if context else [],
    )
]

client.add_signals(signals)

client.send_signals()
