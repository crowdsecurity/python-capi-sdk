import datetime
import logging
import secrets
import time
from collections import defaultdict
from dataclasses import asdict, replace, dataclass
from importlib import metadata
from typing import Dict, Iterable, List, Tuple

import httpx
import jwt
from cscapi.storage import MachineModel, ReceivedDecision, SignalModel, StorageInterface
from more_itertools import batched

__version__ = metadata.version("cscapi").split("+")[0]
null_logger = logging.getLogger("capi-py-sdk")
null_logger.addHandler(logging.NullHandler())

CAPI_BASE_URL = "https://api.crowdsec.net/v3"
CAPI_BASE_DEV_URL = "https://api.dev.crowdsec.net/v3"
CAPI_WATCHER_REGISTER_ENDPOINT = "/watchers"
CAPI_WATCHER_LOGIN_ENDPOINT = "/watchers/login"
CAPI_ENROLL_ENDPOINT = "/watchers/enroll"
CAPI_SIGNALS_ENDPOINT = "/signals"
CAPI_DECISIONS_ENDPOINT = "/decisions/stream"
CAPI_METRICS_ENDPOINT = "/metrics"
SIGNAL_BATCH_LIMIT = 5000


def has_valid_token(
    machine: MachineModel, latency_offset=10, logger: logging.Logger = null_logger
) -> bool:
    logger.debug(f"checking if token is valid for machine {machine.machine_id}")
    try:
        payload = jwt.decode(machine.token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError:
        logger.debug(
            f"could not decode token {machine.token} for machine {machine.machine_id}"
        )
        return False
    current_time = time.time()
    has_enough_ttl = current_time - latency_offset < payload["exp"]
    logger.debug(
        f"token for machine {machine.machine_id} has_enough_ttl = {has_enough_ttl}"
    )
    return has_enough_ttl


@dataclass
class CAPIClientConfig:
    scenarios: List[str]
    prod: bool = False
    user_agent_prefix: str = ""
    max_retries: int = 3
    latency_offset: int = 10
    retry_delay: int = 5
    logger: logging.Logger = null_logger


def _group_signals_by_machine_id(
    signals: Iterable[SignalModel],
) -> Dict[str, List[SignalModel]]:
    signals_by_machineid: Dict[str, List[SignalModel]] = defaultdict(list)
    for signal in signals:
        signals_by_machineid[signal.machine_id].append(signal)
    return signals_by_machineid


class CAPIClient:
    def __init__(self, storage: StorageInterface, config: CAPIClientConfig):
        self.storage = storage
        self.scenarios = ",".join(sorted(config.scenarios))
        self.latency_offset = config.latency_offset
        self.max_retries = config.max_retries
        self.retry_delay = config.retry_delay
        self.logger = config.logger or null_logger

        self.url = CAPI_BASE_URL if config.prod else CAPI_BASE_DEV_URL

        self.http_client = httpx.Client()
        self.http_client.headers.update(
            {"User-Agent": f"{config.user_agent_prefix}-capi-py-sdk/{__version__}"}
        )

    def add_signals(self, signals: List[SignalModel]):
        for signal in signals:
            self.storage.update_or_create_signal(signal)

    def prune_failing_machines_signals(
        self, batch_size: int = SIGNAL_BATCH_LIMIT
    ) -> int:
        total_pruned = 0
        while True:
            signals = self.storage.get_signals(limit=batch_size, is_failing=True)
            if not signals:
                break

            signal_ids = [signal.alert_id for signal in signals]
            self.storage.delete_signals(signal_ids)
            total_pruned += len(signals)

        self.logger.info(f"Total pruned signals: {total_pruned}")
        return total_pruned

    def send_signals(
        self, prune_after_send: bool = True, batch_size: int = SIGNAL_BATCH_LIMIT
    ) -> int:
        offset = 0
        total_sent = 0
        while True:
            signals = self.storage.get_signals(
                limit=batch_size, offset=offset, sent=False, is_failing=False
            )
            if not signals:
                self.logger.info(f"No signals to send, stopping sending")
                break
            unsent_signals_by_machineid = _group_signals_by_machine_id(signals)

            batch_sent = self._send_signals_by_machine_id(
                unsent_signals_by_machineid, prune_after_send
            )
            total_sent += batch_sent

        self.logger.info(f"Total sent signals: {total_sent}")
        return total_sent

    def _has_valid_scenarios(self, machine: MachineModel) -> bool:
        current_scenarios = self.scenarios
        stored_scenarios = machine.scenarios
        if not stored_scenarios:
            return False

        return current_scenarios == stored_scenarios

    def _send_signals_by_machine_id(
        self,
        signals_by_machineid: Dict[str, List[SignalModel]],
        prune_after_send: bool = False,
    ) -> int:
        machines_to_process_attempts: List[MachineModel] = [
            MachineModel(machine_id=machine_id, scenarios=self.scenarios)
            for machine_id in signals_by_machineid.keys()
        ]

        attempt_count = 0
        total_sent = 0

        while machines_to_process_attempts:
            self.logger.info(f"attempt {attempt_count + 1} to send signals")
            retry_machines_to_process_attempts: List[MachineModel] = []
            if attempt_count >= self.max_retries:
                for machine_to_process in machines_to_process_attempts:
                    self.logger.error(
                        f"Machine {machine_to_process.machine_id} is marked as failing"
                    )
                    self.storage.update_or_create_machine(
                        replace(machine_to_process, is_failing=True)
                    )
                break

            for machine_to_process in machines_to_process_attempts:
                machine_to_process = self._prepare_machine(machine_to_process)
                if machine_to_process.is_failing:
                    self.logger.error(
                        f"skipping sending signals for machine {machine_to_process.machine_id} as it's marked as failing"
                    )
                    continue

                self.logger.info(
                    f"sending signals for machine {machine_to_process.machine_id}"
                )
                sent_signal_ids = []
                try:
                    sent_signal_ids = self._send_signals_to_capi(
                        machine_to_process.token,
                        signals_by_machineid[machine_to_process.machine_id],
                    )
                    sent_signal_ids_count = len(sent_signal_ids)
                    total_sent += sent_signal_ids_count
                    self.logger.info(f"sent {sent_signal_ids_count} signals")
                except httpx.HTTPStatusError as exc:
                    self.logger.error(
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
                if prune_after_send and sent_signal_ids:
                    self.logger.info(
                        f"pruning sent signals for machine {machine_to_process.machine_id}"
                    )
                    self.storage.delete_signals(sent_signal_ids)

                self.logger.info(
                    f"sending metrics for machine {machine_to_process.machine_id}"
                )

                try:
                    self._send_metrics_for_machine(machine_to_process)
                except httpx.HTTPStatusError as exc:
                    self.logger.error(
                        f"Error while sending metrics: {exc} for machine {machine_to_process.machine_id}"
                    )

            attempt_count += 1
            machines_to_process_attempts = retry_machines_to_process_attempts
            if retry_machines_to_process_attempts and (
                attempt_count < self.max_retries
            ):
                self.logger.info(
                    f"waiting {self.retry_delay} seconds before retrying sending signals"
                )
                time.sleep(self.retry_delay)

        return total_sent

    def _send_signals_to_capi(
        self, token: str, signals: List[SignalModel]
    ) -> List[int]:
        result = []
        for signal_batch in batched(signals, 250):
            body = [asdict(signal) for signal in signal_batch]
            resp = self.http_client.post(
                self._get_url(CAPI_SIGNALS_ENDPOINT),
                json=body,
                headers={"Authorization": token},
            )
            resp.raise_for_status()
            result.extend(self._mark_signals_as_sent(signal_batch))

        return result

    def _mark_signals_as_sent(self, signals: Tuple[SignalModel]) -> List[int]:
        signal_ids = [signal.alert_id for signal in signals]
        self.storage.mass_update_signals(signal_ids=signal_ids, changes={"sent": True})

        return signal_ids

    def _send_metrics_for_machine(self, machine: MachineModel):
        for _ in range(self.max_retries + 1):
            resp = self.http_client.post(
                self._get_url(CAPI_METRICS_ENDPOINT),
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
                self.logger.error(
                    f"received error {exc} while sending metrics for machine {machine.machine_id}"
                )

    def _refresh_machine_token(self, machine: MachineModel) -> MachineModel:
        machine.scenarios = self.scenarios
        resp = self.http_client.post(
            self._get_url(CAPI_WATCHER_LOGIN_ENDPOINT),
            json={
                "machine_id": machine.machine_id,
                "password": machine.password,
                "scenarios": machine.scenarios.split(","),
            },
        )
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            self.logger.error(
                "Error while refreshing token: machine_id might be already registered or password is wrong"
            )
            raise exc

        new_machine = asdict(machine)
        new_machine["token"] = resp.json()["token"]
        new_machine = MachineModel(**new_machine)
        self.storage.update_or_create_machine(new_machine)
        return new_machine

    def _register_machine(self, machine: MachineModel) -> MachineModel:
        self.logger.info(f"registering machine {machine.machine_id}")
        machine.password = (
            machine.password if machine.password else secrets.token_urlsafe(32)
        )
        resp = self.http_client.post(
            self._get_url(CAPI_WATCHER_REGISTER_ENDPOINT),
            json={
                "machine_id": machine.machine_id,
                "password": machine.password,
            },
        )
        self.storage.update_or_create_machine(machine)
        return machine

    def _prepare_machine(self, machine: MachineModel):
        machine = self._ensure_machine_capi_registered(machine)
        if machine.is_failing:
            self.logger.error(
                f"skipping connection for machine {machine.machine_id} as it's marked as failing"
            )
            return machine

        machine = self._ensure_machine_capi_connected(machine)
        return machine

    def _ensure_machine_capi_registered(self, machine: MachineModel) -> MachineModel:
        retrieved_machine = self.storage.get_machine_by_id(machine.machine_id)
        if not retrieved_machine:
            return self._register_machine(machine)
        return retrieved_machine

    def _ensure_machine_capi_connected(self, machine: MachineModel) -> MachineModel:
        if not has_valid_token(
            machine, self.latency_offset, self.logger
        ) or not self._has_valid_scenarios(machine):
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
            self._get_url(CAPI_DECISIONS_ENDPOINT),
            headers={"Authorization": machine.token},
        )

        return resp.json()

    def _get_url(self, endpoint: str) -> str:
        return self.url + endpoint

    def enroll_machines(
        self,
        machine_ids: List[str],
        name: str,
        attachment_key: str,
        tags: List[str],
        overwrite: bool = False,
    ):
        attempt_count = 0
        next_machine_ids: List[str] = []
        while machine_ids:
            for machine_id in machine_ids:
                machine = self._prepare_machine(MachineModel(machine_id=machine_id))
                if machine.is_failing:
                    self.logger.error(
                        f"skipping enrollment for machine {machine.machine_id} as it's marked as failing"
                    )
                    continue
                try:
                    resp = self.http_client.post(
                        self.url + CAPI_ENROLL_ENDPOINT,
                        json={
                            "name": name,
                            "overwrite": overwrite,
                            "attachment_key": attachment_key,
                            "tags": tags,
                        },
                        headers={"Authorization": machine.token},
                    )
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 401:
                        if attempt_count >= self.max_retries:
                            self.logger.error(
                                f"Error while enrolling machine {machine_id}: {exc}"
                            )
                            continue
                        next_machine_ids.append(machine_id)
                        continue
                    raise exc
            machine_ids = next_machine_ids
            attempt_count += 1
            time.sleep(self.retry_delay)
