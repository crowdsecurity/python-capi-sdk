from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.sql_storage import SQLStorage
from cscapi.utils import create_signal, generate_machine_id_from_key

client = CAPIClient(
    storage=SQLStorage(),
    config=CAPIClientConfig(scenarios=["crowdsecurity/ssh-bf", "acme/http-bf"]),
)

# Fetch signals from your data, and convert it into a list of signals accepted by CrowdSec
signals = [
    create_signal(
        attacker_ip="<attacker_ip>",
        scenario="crowdsecurity/ssh-bf",
        created_at="2023-11-17 10:20:46 +0000",
        machine_id=generate_machine_id_from_key("<key>asd"),
    )
]

# This stores the signals in the database
client.add_signals(signals)

# This sends all the unsent signals to the API.
# You can chron this call to send signals periodically.
client.send_signals()
