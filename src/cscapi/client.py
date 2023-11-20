import secrets
import time
from collections import defaultdict
from dataclasses import asdict
import logging
from typing import Dict, List
from importlib import metadata

import httpx
import jwt
from more_itertools import batched

from cscapi.storage import MachineModel, ReceivedDecision, SignalModel, StorageInterface
from dataclasses import replace


__version__ = metadata.version("cscapi").split("+")[0]

logging.getLogger("capi-py-sdk").addHandler(logging.NullHandler())

CAPI_BASE_URL = "https://api.crowdsec.net/v3"
CAPI_WATCHER_REGISTER_URL = f"{CAPI_BASE_URL}/watchers"
CAPI_WATCHER_LOGIN_URL = f"{CAPI_BASE_URL}/watchers/login"
CAPI_ENROLL_URL = f"{CAPI_BASE_URL}/watchers/enroll"
CAPI_SIGNALS_URL = f"{CAPI_BASE_URL}/signals"
CAPI_DECISIONS_URL = f"{CAPI_BASE_URL}/decisions/stream"


def machine_token_is_valid(token: str) -> bool:
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError:
        return False
    current_time = time.time()
    return current_time < payload["exp"]


class CAPIClient:
    def __init__(self, storage: StorageInterface):
        self.storage = storage
        self.http_client = httpx.Client()
        self.http_client.headers.update({"User-Agent": f"capi-py-sdk/{__version__}"})

    def add_signals(self, signals: List[SignalModel]):
        for signal in signals:
            self.storage.update_or_create_signal(signal)

    def send_signals(self, prune_after_send: bool = False):
        unsent_signals: List[SignalModel] = list(
            filter(lambda signal: not signal.sent, self.storage.get_all_signals())
        )
        signals_by_machineid: Dict[str, List[SignalModel]] = defaultdict(list)
        for signal in unsent_signals:
            signals_by_machineid[signal.machine_id].append(signal)

        machines_to_register = []
        machines_to_login = []
        machines_by_id: Dict[str, MachineModel] = {}

        for machine_id, signals in signals_by_machineid.items():
            machine = self.storage.get_machine_by_id(machine_id)
            signals_scenarios = ",".join(
                sorted(set([signal.scenario for signal in signals]))
            )
            if not machine:
                machines_to_register.append(
                    MachineModel(
                        machine_id=machine_id,
                        scenarios=signals_scenarios,
                        password=secrets.token_urlsafe(22),
                    )
                )

            elif not machine_token_is_valid(machine.token):
                machines_to_login.append(
                    MachineModel(
                        machine_id=machine_id,
                        scenarios=signals_scenarios,
                        password=machine.password,
                    )
                )

            else:
                machines_by_id[machine_id] = machine

        # For higher performance we can use async here.
        updated_machines = list(map(self._make_machine, machines_to_register))
        updated_machines.extend(
            list(map(self._refresh_machine_token, machines_to_login))
        )

        machines_by_id = {
            machine.machine_id: machine for machine in updated_machines
        } | machines_by_id

        for machine_id, signals in signals_by_machineid.items():
            token = machines_by_id[machine_id].token
            self._send_signals(token, signals)

        for signal in unsent_signals:
            self.storage.update_or_create_signal(replace(signal, sent=True))

        if prune_after_send:
            self._prune_sent_signals()

    def _send_signals(self, token: str, signals: SignalModel):
        for signal_batch in batched(signals, 250):
            body = [asdict(signal) for signal in signal_batch]
            resp = self.http_client.post(
                CAPI_SIGNALS_URL, json=body, headers={"Authorization": token}
            )
            resp.raise_for_status()

    def _prune_sent_signals(self):
        signals = filter(lambda signal: signal.sent, self.storage.get_all_signals())
        self.storage.delete_signals(signals)

    def _refresh_machine_token(self, machine: MachineModel) -> MachineModel:
        resp = self.http_client.post(
            CAPI_WATCHER_LOGIN_URL,
            json={
                "machine_id": machine.machine_id,
                "password": machine.password,
                "scenarios": machine.scenarios.split(","),
            },
        )
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logging.error(
                f"Error while refreshing token: machine_id might be already registered or password is wrong"
            )
            raise exc

        new_machine = asdict(machine)
        new_machine["token"] = resp.json()["token"]
        new_machine = MachineModel(**new_machine)
        self.storage.update_or_create_machine(new_machine)
        return new_machine

    def _register_machine(self, machine: MachineModel) -> MachineModel:
        resp = self.http_client.post(
            CAPI_WATCHER_REGISTER_URL,
            json={
                "machine_id": machine.machine_id,
                "password": machine.password,
            },
        )
        self.storage.update_or_create_machine(machine)
        return machine

    def _make_machine(self, machine: MachineModel):
        machine = self._register_machine(machine)
        return self._refresh_machine_token(machine)

    def get_decisions(
        self, main_machine_id: str, scenarios: List[str]
    ) -> List[ReceivedDecision]:
        scenarios = ",".join(sorted(set(scenarios)))
        machine = self.storage.get_machine_by_id(main_machine_id)
        if not machine:
            machine = self._make_machine(
                MachineModel(
                    machine_id=main_machine_id,
                    password=secrets.token_urlsafe(22),
                    scenarios=scenarios,
                )
            )

        elif not machine_token_is_valid(machine.token):
            machine = self._refresh_machine_token(
                MachineModel(
                    machine_id=main_machine_id,
                    password=machine.password,
                    scenarios=scenarios,
                )
            )

        resp = self.http_client.get(
            CAPI_DECISIONS_URL, headers={"Authorization": machine.token}
        )

        return resp.json()

    def enroll_machines(
        self, machine_ids: List[str], name: str, attachment_key: str, tags: List[str]
    ):
        for machine_id in machine_ids:
            machine = self.storage.get_machine_by_id(machine_id)
            if not machine:
                machine = self._make_machine(
                    MachineModel(
                        machine_id=machine_id,
                        password=secrets.token_urlsafe(22),
                        scenarios="",
                    )
                )
            elif not machine_token_is_valid(machine.token):
                machine = self._refresh_machine_token(
                    MachineModel(
                        machine_id=machine_id, password=machine.password, scenarios=""
                    )
                )

            self.http_client.post(
                CAPI_ENROLL_URL,
                json={
                    "name": name,
                    "overwrite": True,
                    "attachment_key": attachment_key,
                    "tags": tags,
                },
            )
