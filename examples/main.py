# Basic Usage

from cscapi.client import CAPIClient
from cscapi.sql_storage import SQLStorage
from cscapi.utils import create_signal, generate_machine_id_from_key

client = CAPIClient(SQLStorage())

signals = [
    create_signal(
        attacker_ip="<attacker_ip>",
        scenario="crowdsecurity/ssh-bf",
        created_at="2023-11-17 10:20:46 +0000",
        machine_id=generate_machine_id_from_key("<key>"),
    )
]

client.add_signals(signals)
client.send_signals()
