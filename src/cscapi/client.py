import datetime
import logging
import secrets
import time
from collections import defaultdict
from dataclasses import asdict, replace
from importlib import metadata
from typing import Dict, Iterable, List

import httpx
import jwt
from more_itertools import batched

from cscapi.storage import MachineModel, ReceivedDecision, SignalModel, StorageInterface

__version__ = metadata.version("cscapi").split("+")[0]

logging.getLogger("capi-py-sdk").addHandler(logging.NullHandler())

CAPI_BASE_URL = "https://api.crowdsec.net/v3"
CAPI_WATCHER_REGISTER_URL = f"{CAPI_BASE_URL}/watchers"
CAPI_WATCHER_LOGIN_URL = f"{CAPI_BASE_URL}/watchers/login"
CAPI_ENROLL_URL = f"{CAPI_BASE_URL}/watchers/enroll"
CAPI_SIGNALS_URL = f"{CAPI_BASE_URL}/signals"
CAPI_DECISIONS_URL = f"{CAPI_BASE_URL}/decisions/stream"
CAPI_METRICS_URL = f"{CAPI_BASE_URL}/metrics"


def has_valid_token(machine: MachineModel, latency_offset=10) -> bool:
    logging.debug(f"checking if token is valid for machine {machine.machine_id}")
    try:
        payload = jwt.decode(machine.token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError:
        logging.debug(
            f"could not decode token {machine.token} for machine {machine.machine_id}"
        )
        return False
    current_time = time.time()
    has_enough_ttl = current_time - latency_offset < payload["exp"]
    logging.debug(
        f"token for machine {machine.machine_id} has_enough_ttl = {has_enough_ttl}"
    )
    return has_enough_ttl


class CAPIClient:
    def __init__(
        self,
        storage: StorageInterface,
        scenarios: List[str],
        max_retries: int = 3,
        latency_offset: int = 10,
        user_agent_prefix: str = "",
        **kwargs,
    ):
        self.storage = storage
        self.scenarios = ",".join(sorted(scenarios))
        self.latency_offset = latency_offset
        self.max_retries = max_retries

        self.http_client = httpx.Client()
        self.http_client.headers.update(
            {"User-Agent": f"{user_agent_prefix}-capi-py-sdk/{__version__}"}
        )

    def add_signals(self, signals: List[SignalModel]):
        for signal in signals:
            self.storage.update_or_create_signal(signal)

    def send_signals(self, prune_after_send: bool = True):
        unsent_signals_by_machineid = self._group_signals_by_machine_id(
            filter(lambda signal: not signal.sent, self.storage.get_all_signals())
        )
        self._send_signals_by_machine_id(unsent_signals_by_machineid, prune_after_send)

    def _group_signals_by_machine_id(
        self, signals: Iterable[SignalModel]
    ) -> Dict[str, List[SignalModel]]:
        signals_by_machineid: Dict[str, List[SignalModel]] = defaultdict(list)
        for signal in signals:
            signals_by_machineid[signal.machine_id].append(signal)
        return signals_by_machineid

    def _send_signals_by_machine_id(
        self,
        signals_by_machineid: Dict[str, List[SignalModel]],
        prune_after_send: bool = False,
    ):
        machines_to_process_attempts: List[MachineModel] = [
            MachineModel(machine_id=machine_id, scenarios=self.scenarios)
            for machine_id in signals_by_machineid.keys()
        ]

        retry_machines_to_process_attempts: List[MachineModel] = []
        attempt_count = 0

        while machines_to_process_attempts:
            logging.info(f"attempt {attempt_count} to send signals")
            if attempt_count > self.max_retries:
                for machine_to_process in machines_to_process_attempts:
                    logging.error(
                        f"Machine {machine_to_process.machine_id} is marked as failing"
                    )
                    self.storage.update_or_create_machine(
                        replace(machine_to_process, is_failing=True)
                    )
                break

            for machine_to_process in machines_to_process_attempts:
                machine_to_process = self._prepare_machine(machine_to_process)
                if machine_to_process.is_failing:
                    logging.error(
                        f"skipping sending signals for machine {machine_to_process.machine_id} as it's marked as failing"
                    )
                    continue

                logging.info(
                    f"sending signals for machine {machine_to_process.machine_id}"
                )
                try:
                    self._send_signals(
                        machine_to_process.token,
                        signals_by_machineid[machine_to_process.machine_id],
                    )
                except httpx.HTTPStatusError as exc:
                    logging.error(
                        f"error while sending signals: {exc} for machine {machine_to_process.machine_id}"
                    )
                    if exc.response.status_code == 401:
                        if attempt_count >= self.max_retries:
                            self.storage.update_or_create_machine(
                                replace(machine_to_process, is_failing=True)
                            )
                            continue
                        machine_to_process.token = None
                        retry_machines_to_process_attempts.append(machine_to_process)
                        continue
                if prune_after_send:
                    logging.info(
                        f"pruning sent signals for machine {machine_to_process.machine_id}"
                    )
                    self._prune_sent_signals()

                logging.info(
                    f"sending metrics for machine {machine_to_process.machine_id}"
                )

                try:
                    self._send_metrics_for_machine(machine_to_process)
                except httpx.HTTPStatusError as exc:
                    logging.error(
                        f"Error while sending metrics: {exc} for machine {machine_to_process.machine_id}"
                    )

            attempt_count += 1
            machines_to_process_attempts = retry_machines_to_process_attempts

    def _send_signals(self, token: str, signals: SignalModel):
        for signal_batch in batched(signals, 250):
            body = [asdict(signal) for signal in signal_batch]
            resp = self.http_client.post(
                CAPI_SIGNALS_URL, json=body, headers={"Authorization": token}
            )
            resp.raise_for_status()
            self._mark_signals_as_sent(signal_batch)

    def _mark_signals_as_sent(self, signals: List[SignalModel]):
        for signal in signals:
            self.storage.update_or_create_signal(replace(signal, sent=True))

    def _send_metrics_for_machine(self, machine: MachineModel):
        for _ in range(self.max_retries + 1):
            resp = self.http_client.post(
                CAPI_METRICS_URL,
                json={
                    "bouncers": [],
                    "machines": [
                        {
                            "last_update": datetime.datetime.now().isoformat(),
                            "last_push": datetime.datetime.now().isoformat(),
                            "version": __version__,
                            "name": machine.machine_id,
                        }
                    ],
                },
                headers={"Authorization": machine.token},
            )
            try:
                resp.raise_for_status()
                break
            except httpx.HTTPStatusError as exc:
                logging.error(
                    f"received error {exc} while sending metrics for machine {machine.machine_id}"
                )
                time.sleep(5)

    def _prune_sent_signals(self):
        signals = list(
            filter(lambda signal: signal.sent, self.storage.get_all_signals())
        )

        self.storage.delete_signals(signals)

    def _clear_all_signals(self):
        signals = self.storage.get_all_signals()
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
                "Error while refreshing token: machine_id might be already registered or password is wrong"
            )
            raise exc

        new_machine = asdict(machine)
        new_machine["token"] = resp.json()["token"]
        new_machine = MachineModel(**new_machine)
        self.storage.update_or_create_machine(new_machine)
        return new_machine

    def _register_machine(self, machine: MachineModel) -> MachineModel:
        logging.info(f"registering machine {machine.machine_id}")
        machine.password = (
            machine.password if machine.password else secrets.token_urlsafe(32)
        )
        resp = self.http_client.post(
            CAPI_WATCHER_REGISTER_URL,
            json={
                "machine_id": machine.machine_id,
                "password": machine.password,
            },
        )
        self.storage.update_or_create_machine(machine)
        return machine

    def _prepare_machine(self, machine: MachineModel):
        machine = self._ensure_machine_capi_registered(machine)
        machine = self._ensure_machine_capi_connected(machine)
        return machine

    def _ensure_machine_capi_registered(self, machine: MachineModel) -> MachineModel:
        retrieved_machine = self.storage.get_machine_by_id(machine.machine_id)
        if not retrieved_machine:
            return self._register_machine(machine)
        return retrieved_machine

    def _ensure_machine_capi_connected(self, machine: MachineModel) -> MachineModel:
        if not has_valid_token(machine, self.latency_offset):
            return self._refresh_machine_token(machine)
        return machine

    def get_decisions(
        self, main_machine_id: str, scenarios: List[str]
    ) -> List[ReceivedDecision]:
        scenarios = ",".join(sorted(set(scenarios)))
        machine = self._prepare_machine(
            MachineModel(machine_id=main_machine_id, scenarios=scenarios)
        )
        resp = self.http_client.get(
            CAPI_DECISIONS_URL, headers={"Authorization": machine.token}
        )

        return resp.json()

    def enroll_machines(
        self, machine_ids: List[str], name: str, attachment_key: str, tags: List[str]
    ):
        attempt_count = 0
        next_machine_ids: List[str] = []
        while machine_ids:
            for machine_id in machine_ids:
                machine = self._prepare_machine(MachineModel(machine_id=machine_id))
                try:
                    resp = self.http_client.post(
                        CAPI_ENROLL_URL,
                        json={
                            "name": name,
                            "overwrite": False,
                            "attachment_key": attachment_key,
                            "tags": tags,
                        },
                        headers={"Authorization": machine.token},
                    )
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 401:
                        if attempt_count >= self.max_retries:
                            logging.error(
                                f"Error while enrolling machine {machine_id}: {exc}"
                            )
                            continue
                        next_machine_ids.append(machine_id)
                        continue
                    raise exc
            machine_ids = next_machine_ids
            attempt_count += 1
            time.sleep(5)
