from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.sql_storage import SQLStorage
from cscapi.utils import create_signal, generate_machine_id_from_key

client = CAPIClient(
    storage=SQLStorage(),
    config=CAPIClientConfig(
        scenarios=["acme/http-bf", "crowdsec/ssh-bf"],
        user_agent_prefix="example",
        prod=False,
    ),
)

# Fetch signals from your data, and convert it into a list of signals accepted by CrowdSec
signals = [
    create_signal(
        attacker_ip="81.81.81.81",
        scenario="pysdktest/test-sc",
        created_at="2024-01-19 12:12:21 +0000",
        machine_id=generate_machine_id_from_key("myMachineKeyIdentifier"),
        context=[{"key": "scenario-version", "value": "1.0.0"}],
        message="test message to see where it is written",
        decisions=[
            {
                "origin": "crowdsec",
                "duration": "1h",
                "scenario": "crowdsec/ssh-bf",
                "scope": "ip",
                "type": "ban",
                "value": "81.81.81.81",
            },
            {
                "origin": "pysdk",
                "duration": "2h",
                "scenario": "crowdsec/ssh-bf",
                "scope": "ip",
                "type": "ban",
                "value": "81.81.81.81",
            },
        ],
    )
]

# This stores the signals in the database
client.add_signals(signals)

# This sends all the unsent signals to the API.
# You can chron this call to send signals periodically.
client.send_signals()

# client.enroll_machines([generate_machine_id_from_key("myMachineId")], "basicExample", "myenrollkeyigotonconsole", [])
