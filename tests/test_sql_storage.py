import os
import time
from unittest import TestCase
import pytest
import random

from dacite import from_dict

from cscapi.sql_storage import (
    ContextDBModel,
    DecisionDBModel,
    MachineDBModel,
    SignalDBModel,
    SourceDBModel,
    SQLStorage,
)
from cscapi.storage import MachineModel, SourceModel, SignalModel

from cscapi.client import (
    CAPIClient,
    CAPIClientConfig,
)

from sqlalchemy_utils import database_exists, create_database, drop_database

from .test_client import mock_signals


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


class TestSQLStorage(TestCase):
    def setUp(self) -> None:
        self.db_path = f"{str(int(time.time()))}.db"
        # Use .env file to modify variables
        engine_type = (
            os.getenv("TEST_SQL_ENGINE") if os.getenv("TEST_SQL_ENGINE") else "sqlite"
        )
        if engine_type == "sqlite":
            db_uri = f"sqlite:///{self.db_path}"
        elif engine_type == "postgres":
            db_uri = f"{os.getenv('TEST_POSTGRESQL_URL')}{self.db_path}"
        elif engine_type == "mysql":
            db_uri = f"{os.getenv('TEST_MYSQL_URL')}{self.db_path}"
        elif engine_type == "mariadb":
            db_uri = f"{os.getenv('TEST_MARIADB_URL')}{self.db_path}"
        else:
            raise ValueError(f"Unknown engine type: {engine_type}")
        if not database_exists(db_uri):
            create_database(db_uri)

        self.storage: SQLStorage = SQLStorage(db_uri)
        self.db_uri = db_uri
        print(f"Using {engine_type} engine with {db_uri}")

        self.client = CAPIClient(
            self.storage,
            CAPIClientConfig(
                scenarios=["crowdsecurity/http-bf", "crowdsecurity/ssh-bf"],
                max_retries=1,
                retry_delay=0,
            ),
        )

    def tearDown(self) -> None:
        # postgresql, mysql, mariadb
        if database_exists(self.db_uri):
            try:
                drop_database(self.db_uri)
            except Exception as e:
                print(f"Error occurred while dropping the database: {e}")

        # sqlite
        try:
            os.remove(self.db_path)
        except:
            pass

    def test_get_signals_with_no_machine(self):
        assert len(self.storage.get_signals(limit=1000)) == 0
        for x in range(10):
            self.client.add_signals(mock_signals())
            time.sleep(0.05)
        assert len(self.storage.get_signals(limit=1000)) == 10
        assert len(self.storage.get_signals(limit=5)) == 5
        assert len(self.storage.get_signals(limit=5, offset=8)) == 2
        assert len(self.storage.get_signals(limit=1000, sent=True)) == 0
        assert len(self.storage.get_signals(limit=1000, sent=False)) == 10
        assert len(self.storage.get_signals(limit=1000, is_failing=True)) == 0
        assert len(self.storage.get_signals(limit=1000, is_failing=False)) == 10
        assert (
            len(self.storage.get_signals(limit=1000, sent=False, is_failing=False))
            == 10
        )
        assert (
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=False)) == 0
        )

    def test_get_signals_with_machine(self):
        m1 = MachineModel(
            machine_id="test",  # Same machine_id as in mock_signals
            token="1",
            password="1",
            scenarios="crowdsecurity/http-probing",
        )
        self.assertTrue(self.storage.update_or_create_machine(m1))
        assert len(self.storage.get_signals(limit=1000)) == 0
        for x in range(10):
            self.client.add_signals(mock_signals())
            time.sleep(0.05)
        assert len(self.storage.get_signals(limit=1000)) == 10
        assert len(self.storage.get_signals(limit=5)) == 5
        assert len(self.storage.get_signals(limit=5, offset=8)) == 2
        assert len(self.storage.get_signals(limit=1000, sent=True)) == 0
        assert len(self.storage.get_signals(limit=1000, sent=False)) == 10
        assert len(self.storage.get_signals(limit=1000, is_failing=True)) == 0
        assert len(self.storage.get_signals(limit=1000, is_failing=False)) == 10
        assert (
            len(self.storage.get_signals(limit=1000, sent=False, is_failing=False))
            == 10
        )
        assert (
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=False)) == 0
        )

    def test_get_signals_with_failing_machine(self):
        m1 = MachineModel(
            machine_id="test",  # Same machine_id as in mock_signals
            token="1",
            password="1",
            scenarios="crowdsecurity/http-probing",
            is_failing=True,
        )
        self.assertTrue(self.storage.update_or_create_machine(m1))
        assert len(self.storage.get_signals(limit=1000)) == 0
        for x in range(10):
            self.client.add_signals(mock_signals())
            time.sleep(0.05)
        assert len(self.storage.get_signals(limit=1000)) == 10
        assert len(self.storage.get_signals(limit=5)) == 5
        assert len(self.storage.get_signals(limit=5, offset=8)) == 2
        assert len(self.storage.get_signals(limit=1000, sent=True)) == 0
        assert len(self.storage.get_signals(limit=1000, sent=False)) == 10
        assert len(self.storage.get_signals(limit=1000, is_failing=True)) == 10
        assert len(self.storage.get_signals(limit=1000, is_failing=False)) == 0
        assert (
            len(self.storage.get_signals(limit=1000, sent=False, is_failing=False)) == 0
        )
        assert (
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=False)) == 0
        )
        assert (
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=True)) == 0
        )

    def test_create_and_retrieve_machine(self):
        m1 = MachineModel(
            machine_id="1",
            token="1",
            password="1",
            scenarios="crowdsecurity/http-probing",
        )

        # Should return true if db row is created, else return false
        self.assertTrue(self.storage.update_or_create_machine(m1))
        self.assertFalse(self.storage.update_or_create_machine(m1))

        retrieved = self.storage.get_machine_by_id("1")

        self.assertEqual(retrieved.machine_id, m1.machine_id)
        self.assertEqual(retrieved.token, m1.token)
        self.assertEqual(retrieved.password, m1.password)
        self.assertEqual(retrieved.scenarios, m1.scenarios)

    def test_update_machine(self):
        m1 = MachineModel(
            machine_id="1",
            token="1",
            password="1",
            scenarios="crowdsecurity/http-probing",
        )
        self.storage.update_or_create_machine(m1)

        retrieved = self.storage.get_machine_by_id("1")

        self.assertEqual(retrieved.machine_id, m1.machine_id)
        self.assertEqual(retrieved.token, m1.token)
        self.assertEqual(retrieved.password, m1.password)
        self.assertEqual(retrieved.scenarios, m1.scenarios)

        m2 = MachineModel(
            machine_id="1", token="2", password="2", scenarios="crowdsecurity/http-bf"
        )
        self.storage.update_or_create_machine(m2)
        with self.storage.session.begin() as session:
            self.assertEqual(1, session.query(MachineDBModel).count())

        retrieved = self.storage.get_machine_by_id("1")

        self.assertEqual(retrieved.machine_id, m2.machine_id)
        self.assertEqual(retrieved.token, m2.token)
        self.assertEqual(retrieved.password, m2.password)
        self.assertEqual(retrieved.scenarios, m2.scenarios)

    def test_create_signal(self):
        assert self.storage.get_signals(limit=1000) == []
        self.storage.update_or_create_signal(mock_signals()[0])
        signals = self.storage.get_signals(limit=1000)
        assert len(signals) == 1
        signal = signals[0]

        assert signal.alert_id is not None
        assert signal.sent == False

        with self.storage.session.begin() as session:
            assert session.query(SignalDBModel).count() == 1
            assert session.query(ContextDBModel).count() == 4
            assert session.query(DecisionDBModel).count() == 1
            assert session.query(SourceDBModel).count() == 1
        assert len(signal.context) == 4

        assert len(signal.decisions) == 1

        assert isinstance(signal.source, SourceModel)

    def test_update_signal(self):
        assert self.storage.get_signals(limit=1000) == []

        to_insert = mock_signals()[0]
        self.storage.update_or_create_signal(to_insert)
        signals = self.storage.get_signals(limit=1000)

        assert len(signals) == 1
        signal = signals[0]

        assert signal.sent == False

        signal.sent = True

        self.storage.update_or_create_signal(signal)
        signals = self.storage.get_signals(limit=1000)

        assert len(signals) == 1
        signal = signals[0]

        assert signal.sent == True
