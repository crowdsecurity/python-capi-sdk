"""

Send Signals
1. Send signals from fresh state. Assert machine creation, token creation, correct scenarios etc.
2. Send signals except the machines are already in the DB. Assert no new registrations 
3. Send signals except the machines are already in the DB but tokens are stale. Assert new tokens are created
4. Send signals except some machines are fresh, some have stale token, some are good to send. 

Get decisions
1. Get decisions from fresh machine
2. Get decisions from alright machine
3. Get decisions from stale token machine

Enroll

1. Enroll from fresh machine
2. Enroll from alright machine
3. Enroll from stale token machine

"""

import json
import os
import random
import time
from dataclasses import asdict, replace

import httpx
import jwt
import pytest
from dacite import from_dict
from pytest_httpx import HTTPXMock

from cscapi.client import (
    CAPI_BASE_URL,
    CAPI_BASE_DEV_URL,
    CAPI_DECISIONS_ENDPOINT,
    CAPI_ENROLL_ENDPOINT,
    CAPI_SIGNALS_ENDPOINT,
    CAPI_WATCHER_LOGIN_ENDPOINT,
    CAPI_WATCHER_REGISTER_ENDPOINT,
    CAPI_METRICS_ENDPOINT,
    CAPIClient,
    has_valid_token,
    CAPIClientConfig,
)
from cscapi.sql_storage import SQLStorage
from cscapi.storage import MachineModel, SignalModel


def mock_signals():
    return [
        from_dict(SignalModel, z)
        for z in [
            {
                "decisions": [
                    {
                        "duration": "59m49.264032632s",
                        "id": random.randint(0, 100000),
                        "origin": "crowdsec",
                        "scenario": "crowdsecurity/ssh-bf",
                        "scope": "Ip",
                        "simulated": False,
                        "type": "ban",
                        "value": "1.1.1.172",
                    }
                ],
                "context": [
                    {"key": "target_user", "value": "netflix"},
                    {"key": "service", "value": "ssh"},
                    {"key": "target_user", "value": "netflix"},
                    {"key": "service", "value": "ssh"},
                ],
                "uuid": "1",
                "machine_id": "test",
                "message": "Ip 1.1.1.172 performed 'crowdsecurity/ssh-bf' (6 events over 2.920062ms) at 2020-11-28 10:20:46.845619968 +0100 CET m=+5.903899761",
                "scenario": "crowdsecurity/ssh-bf",
                "scenario_hash": "4441dcff07020f6690d998b7101e642359ba405c2abb83565bbbdcee36de280f",
                "scenario_version": "0.1",
                "scenario_trust": "trusted",
                "source": {
                    "as_name": "Cloudflare Inc",
                    "cn": "AU",
                    "ip": "1.1.1.172",
                    "latitude": -37.7,
                    "longitude": 145.1833,
                    "range": "1.1.1.0/24",
                    "scope": "Ip",
                    "value": "1.1.1.172",
                },
                "start_at": "2020-11-28 10:20:46.842701127 +0100 +0100",
                "stop_at": "2020-11-28 10:20:46.845621385 +0100 +0100",
                "created_at": "2020-11-28T10:20:47+01:00",
            }
        ]
    ]


@pytest.fixture
def storage():
    db_name = f"{time.time()}.db"
    storage = SQLStorage(f"sqlite:///{db_name}")
    yield storage
    storage.session.close()
    try:
        os.remove(db_name)
    except:
        pass


@pytest.fixture
def client(storage):
    return CAPIClient(
        storage,
        CAPIClientConfig(
            scenarios=["crowdsecurity/http-bf", "crowdsecurity/ssh-bf"],
            max_retries=1,
            retry_delay=0,
        ),
    )


@pytest.fixture
def prod_client(storage):
    return CAPIClient(
        storage,
        CAPIClientConfig(
            prod=True,
            scenarios=["crowdsecurity/http-bf", "crowdsecurity/ssh-bf"],
            max_retries=0,
            retry_delay=0,
        ),
    )


class TestChooseEnv:
    def test_handle_dev_url(self, client: CAPIClient, httpx_mock: HTTPXMock):
        assert client.url == CAPI_BASE_DEV_URL

        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token()},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="GET",
            url=CAPI_BASE_DEV_URL + CAPI_DECISIONS_ENDPOINT,
            json={"new": [asdict(mock_signals()[0].decisions[0])], "deleted": []},
        )

        client.get_decisions("test", ["crowdsecurity/http-bf"])

        requests = httpx_mock.get_requests()

        assert requests[0].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT

    def test_handle_prod_url(self, prod_client: CAPIClient, httpx_mock: HTTPXMock):
        assert prod_client.url == CAPI_BASE_URL

        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token()},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="GET",
            url=CAPI_BASE_URL + CAPI_DECISIONS_ENDPOINT,
            json={"new": [asdict(mock_signals()[0].decisions[0])], "deleted": []},
        )

        prod_client.get_decisions("test", ["crowdsecurity/http-bf"])

        requests = httpx_mock.get_requests()

        assert requests[0].url == CAPI_BASE_URL + CAPI_WATCHER_REGISTER_ENDPOINT


class TestSendSignals:
    def test_fresh_send_signals(self, httpx_mock: HTTPXMock, client: CAPIClient):
        assert len(client.storage.get_all_signals()) == 0
        token = dummy_token()
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": token},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT, text="OK"
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_METRICS_ENDPOINT, text="OK"
        )

        s1 = replace(mock_signals()[0], scenario="crowdsecurity/http-bf")
        s2 = mock_signals()[0]
        client.add_signals([s1, s2])
        assert len(client.storage.get_all_signals()) == 2

        assert client.storage.get_machine_by_id("test") is None

        client.send_signals()

        machine = client.storage.get_machine_by_id("test")
        assert machine is not None
        assert machine.token == token
        assert machine.password is not None
        assert machine.scenarios == client.scenarios

        requests = httpx_mock.get_requests()
        assert len(requests) == 4

        assert requests[0].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT
        assert requests[0].method == "POST"

        assert requests[1].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT
        assert requests[1].method == "POST"

        assert requests[2].url == CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT
        assert requests[2].method == "POST"

        assert requests[3].url == CAPI_BASE_DEV_URL + CAPI_METRICS_ENDPOINT
        assert requests[3].method == "POST"

    def test_signal_gets_deleted_after_send(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        assert len(client.storage.get_all_signals()) == 0
        token = dummy_token()
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": token},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT, text="OK"
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_METRICS_ENDPOINT, text="OK"
        )

        s1 = mock_signals()[0]
        client.add_signals([s1])
        assert len(client.storage.get_all_signals()) == 1
        client.send_signals(prune_after_send=True)
        assert len(client.storage.get_all_signals()) == 0

    def test_signals_from_already_registered_machine(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token()},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT, text="OK"
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_METRICS_ENDPOINT, text="OK"
        )

        assert client.storage.get_machine_by_id("test") is None

        client._prepare_machine(
            MachineModel("test", "abcd", "crowdsecurity/http-bf,crowdsecurity/ssh-bf")
        )

        requests = httpx_mock.get_requests()

        assert len(requests) == 2

        assert requests[0].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT
        assert requests[0].method == "POST"

        assert requests[1].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT
        assert requests[1].method == "POST"

        assert client.storage.get_machine_by_id("test") is not None

        client.add_signals(mock_signals())
        client.send_signals()

        requests = httpx_mock.get_requests()

        assert len(requests) == 4

        assert requests[2].url == CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT
        assert requests[2].method == "POST"

        assert requests[3].url == CAPI_BASE_DEV_URL + CAPI_METRICS_ENDPOINT
        assert requests[3].method == "POST"

    def test_signals_from_already_registered_machine_with_stale_token(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        token = dummy_token(exp=int(time.time()) - 3600)
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": token},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT, text="OK"
        )
        httpx_mock.add_response(
            method="POST", url=CAPI_BASE_DEV_URL + CAPI_METRICS_ENDPOINT, text="OK"
        )

        assert client.storage.get_machine_by_id("test") is None

        client._prepare_machine(
            MachineModel("test", "abcd", "crowdsecurity/http-bf,crowdsecurity/ssh-bf")
        )

        requests = httpx_mock.get_requests()

        assert len(requests) == 2

        assert requests[0].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT
        assert requests[0].method == "POST"

        assert requests[1].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT
        assert requests[1].method == "POST"

        assert client.storage.get_machine_by_id("test") is not None

        client.add_signals(mock_signals())
        client.send_signals()

        requests = httpx_mock.get_requests()
        assert len(requests) == 5

        assert requests[2].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT
        assert requests[2].method == "POST"

        assert requests[3].url == CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT
        assert requests[3].method == "POST"

    def test_signals_from_mixed_machines(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        fresh_mid, stale_mid, good_mid = "fresh", "stale", "good"
        stale_token = dummy_token(exp=int(time.time()) - 3600)
        good_token = dummy_token()

        signals = [
            replace(mock_signals()[0], machine_id="fresh"),
            replace(mock_signals()[0], machine_id="stale"),
            replace(mock_signals()[0], machine_id="good"),
        ]

        def resp(request: httpx.Request):
            if request.url == CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT:
                machine_id = json.loads(request.content)["machine_id"]
                if machine_id == "fresh":
                    return httpx.Response(
                        status_code=200, json={"token": dummy_token()}
                    )
                elif machine_id == "stale":
                    return httpx.Response(status_code=200, json={"token": stale_token})
                elif machine_id == "good":
                    return httpx.Response(status_code=200, json={"token": good_token})
            elif request.url == CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT:
                return httpx.Response(status_code=200, json={"message": "OK"})
            elif request.url == CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT:
                return httpx.Response(status_code=200, json="OK")
            elif request.url == CAPI_BASE_DEV_URL + CAPI_METRICS_ENDPOINT:
                return httpx.Response(status_code=200, json="OK")

        httpx_mock.add_callback(resp)

        assert len(httpx_mock.get_requests()) == 0

        # stale machine
        assert client.storage.get_machine_by_id(stale_mid) is None
        client._prepare_machine(
            MachineModel(
                stale_mid, scenarios="crowdsecurity/http-bf,crowdsecurity/ssh-bf"
            )
        )
        assert client.storage.get_machine_by_id(stale_mid) is not None
        assert len(httpx_mock.get_requests()) == 2

        # good machine
        assert client.storage.get_machine_by_id(good_mid) is None
        client._prepare_machine(
            MachineModel(
                good_mid, scenarios="crowdsecurity/http-bf,crowdsecurity/ssh-bf"
            )
        )
        assert client.storage.get_machine_by_id(good_mid) is not None
        assert len(httpx_mock.get_requests()) == 4

        client.add_signals(signals)

        assert client.storage.get_machine_by_id(fresh_mid) is None

        client.send_signals()
        # stale machine makes 1 req to refresh token
        # fresh machine makes 2 reqs to register and login

        # good machine makes 1 req to send signals and 1 req to send metrics
        # fresh machine makes 1 req to send signals and 1 req to send metrics
        # stale machine makes 1 req to send signals and 1 req to send metrics

        assert len(httpx_mock.get_requests()) == 13

        assert client.storage.get_machine_by_id(fresh_mid) is not None

    def test_signals_with_retry(self, httpx_mock: HTTPXMock, client: CAPIClient):
        stale_token = dummy_token(exp=int(time.time()) - 3600)
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": stale_token},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_SIGNALS_ENDPOINT,
            text="OK",
            status_code=401,
        )
        machine = MachineModel(
            machine_id="test",
            token=stale_token,
            scenarios="crowdsecurity/http-bf,crowdsecurity/ssh-bf",
        )
        client.storage.update_or_create_machine(machine)
        client.add_signals(mock_signals())
        client.send_signals()
        machine = client.storage.get_machine_by_id("test")
        assert machine.is_failing == True


class TestGetDecisions:
    def test_get_decisions_from_fresh_machine(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token()},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="GET",
            url=CAPI_BASE_DEV_URL + CAPI_DECISIONS_ENDPOINT,
            json={"new": [asdict(mock_signals()[0].decisions[0])], "deleted": []},
        )

        assert client.storage.get_machine_by_id("test") is None

        client.get_decisions("test", ["crowdsecurity/http-bf"])

        requests = httpx_mock.get_requests()

        assert len(requests) == 3

        assert requests[0].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT
        assert requests[0].method == "POST"

        assert requests[1].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT
        assert requests[1].method == "POST"

        assert requests[2].url == CAPI_BASE_DEV_URL + CAPI_DECISIONS_ENDPOINT
        assert requests[2].method == "GET"

    def test_get_decisions_from_registered_machine_with_valid_token(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token()},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="GET",
            url=CAPI_BASE_DEV_URL + CAPI_DECISIONS_ENDPOINT,
            json={"new": [asdict(mock_signals()[0].decisions[0])], "deleted": []},
        )

        m1 = MachineModel("test")

        assert client.storage.get_machine_by_id("test") is None
        client._prepare_machine(m1)

        assert len(httpx_mock.get_requests()) == 2
        assert client.storage.get_machine_by_id("test") is not None

        client.get_decisions("test", ["crowdsecurity/http-bf"])
        assert len(httpx_mock.get_requests()) == 3

    def test_get_decisions_from_registered_machine_with_expired_token(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token(exp=int(time.time()) - 3600)},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="GET",
            url=CAPI_BASE_DEV_URL + CAPI_DECISIONS_ENDPOINT,
            json={"new": [asdict(mock_signals()[0].decisions[0])], "deleted": []},
        )

        m1 = MachineModel("test")

        assert client.storage.get_machine_by_id("test") is None
        client._prepare_machine(m1)

        assert len(httpx_mock.get_requests()) == 2
        assert client.storage.get_machine_by_id("test") is not None

        client.get_decisions("test", ["crowdsecurity/http-bf"])
        assert len(httpx_mock.get_requests()) == 4


class TestEnroll:
    def test_enroll_from_fresh_machines(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token()},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_ENROLL_ENDPOINT,
            json={"message": "OK"},
        )

        assert client.storage.get_machine_by_id("test") is None
        assert client.storage.get_machine_by_id("test1") is None

        client.enroll_machines(
            ["test", "test1"],
            ["crowdsecurity/http-bf"],
            attachment_key="toto",
            tags=["toto"],
        )

        requests = httpx_mock.get_requests()

        assert len(requests) == 6  # For each machine, 1 register, 1 login, 1 enroll

        assert requests[0].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT
        assert requests[1].url == CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT
        assert requests[2].url == CAPI_BASE_DEV_URL + CAPI_ENROLL_ENDPOINT

    def test_enroll_from_registered_machine_with_valid_token(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token()},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_ENROLL_ENDPOINT,
            json={"message": "OK"},
        )

        assert client.storage.get_machine_by_id("test") is None

        client._prepare_machine(MachineModel("test"))

        assert len(httpx_mock.get_requests()) == 2
        assert client.storage.get_machine_by_id("test") is not None

        client.enroll_machines(
            ["test"], ["crowdsecurity/http-bf"], attachment_key="toto", tags=["toto"]
        )

        requests = httpx_mock.get_requests()
        assert len(requests) == 3

    def test_enroll_from_registered_machine_with_expired_token(
        self, httpx_mock: HTTPXMock, client: CAPIClient
    ):
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_LOGIN_ENDPOINT,
            json={"token": dummy_token(exp=int(time.time()) - 3600)},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_WATCHER_REGISTER_ENDPOINT,
            json={"message": "OK"},
        )
        httpx_mock.add_response(
            method="POST",
            url=CAPI_BASE_DEV_URL + CAPI_ENROLL_ENDPOINT,
            json={"message": "OK"},
        )

        assert client.storage.get_machine_by_id("test") is None

        client._prepare_machine(MachineModel("test"))

        assert len(httpx_mock.get_requests()) == 2
        assert client.storage.get_machine_by_id("test") is not None

        client.enroll_machines(
            ["test"], ["crowdsecurity/http-bf"], attachment_key="toto", tags=["toto"]
        )

        requests = httpx_mock.get_requests()
        assert len(requests) == 4


def dummy_token(exp=None):
    if not exp:
        exp = int(time.time()) + 3600
    return jwt.encode(
        {
            "sub": "toto",
            "aud": "toto",
            "iss": "https://api.dev.crowdsec.net",
            "iat": int(time.time()),
            "exp": exp,
            "cognito:username": "toto",
            "push_interval_seconds": 10,
        },
        "secret",
        algorithm="HS256",
    )
