import random
import os
import time
from unittest import TestCase

from dacite import from_dict
from mongoengine import disconnect

from cscapi.client import CAPIClient, CAPIClientConfig
from cscapi.mongodb_storage import MachineDBModel, MongoDBStorage, SignalDBModel
from cscapi.storage import MachineModel, SignalModel, SourceModel


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


class TestMongoDBStorage(TestCase):
    storage = None

    @classmethod
    def setUpClass(cls):
        # Use .env file to modify variables
        mongodb_connection = (
            os.getenv("TEST_MONGODB_CONNECTION")
            if os.getenv("TEST_MONGODB_CONNECTION")
            else "mongodb://127.0.0.1:27017/cscapi_test"
        )
        cls.storage: MongoDBStorage = MongoDBStorage(
            connection_string=mongodb_connection
        )
        cls.client = CAPIClient(
            cls.storage,
            CAPIClientConfig(
                scenarios=["crowdsecurity/http-bf", "crowdsecurity/ssh-bf"],
                max_retries=1,
                retry_delay=0,
            ),
        )

    @classmethod
    def tearDownClass(cls):
        disconnect()

    def setUp(self):
        SignalDBModel.objects.all().delete()
        MachineDBModel.objects.all().delete()

    def tearDown(self):
        SignalDBModel.objects.all().delete()
        MachineDBModel.objects.all().delete()

    def test_get_signals_with_no_machine(self):
        self.assertEqual(len(self.storage.get_signals(limit=1000)), 0)
        for x in range(10):
            self.client.add_signals(mock_signals())
            time.sleep(0.05)
        self.assertEqual(len(self.storage.get_signals(limit=1000)), 10)
        self.assertEqual(len(self.storage.get_signals(limit=5)), 5)
        self.assertEqual(len(self.storage.get_signals(limit=5, offset=8)), 2)
        self.assertEqual(len(self.storage.get_signals(limit=1000, sent=True)), 0)
        self.assertEqual(len(self.storage.get_signals(limit=1000, sent=False)), 10)
        self.assertEqual(len(self.storage.get_signals(limit=1000, is_failing=True)), 0)
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, is_failing=False)), 10
        )
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, sent=False, is_failing=False)), 10
        )
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=False)), 0
        )

    def test_get_signals_with_machine(self):
        m1 = MachineModel(
            machine_id="test",  # Same machine_id as in mock_signals
            token="1",
            password="1",
            scenarios="crowdsecurity/http-probing",
        )
        self.assertTrue(self.storage.update_or_create_machine(m1))
        self.assertEqual(len(self.storage.get_signals(limit=1000)), 0)
        for x in range(10):
            self.client.add_signals(mock_signals())
            time.sleep(0.05)
        self.assertEqual(len(self.storage.get_signals(limit=1000)), 10)
        self.assertEqual(len(self.storage.get_signals(limit=5)), 5)
        self.assertEqual(len(self.storage.get_signals(limit=5, offset=8)), 2)
        self.assertEqual(len(self.storage.get_signals(limit=1000, sent=True)), 0)
        self.assertEqual(len(self.storage.get_signals(limit=1000, sent=False)), 10)
        self.assertEqual(len(self.storage.get_signals(limit=1000, is_failing=True)), 0)
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, is_failing=False)), 10
        )
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, sent=False, is_failing=False)), 10
        )
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=False)), 0
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
        self.assertEqual(len(self.storage.get_signals(limit=1000)), 0)
        for x in range(10):
            self.client.add_signals(mock_signals())
            time.sleep(0.05)
        self.assertEqual(len(self.storage.get_signals(limit=1000)), 10)
        self.assertEqual(len(self.storage.get_signals(limit=5)), 5)
        self.assertEqual(len(self.storage.get_signals(limit=5, offset=8)), 2)
        self.assertEqual(len(self.storage.get_signals(limit=1000, sent=True)), 0)
        self.assertEqual(len(self.storage.get_signals(limit=1000, sent=False)), 10)
        self.assertEqual(len(self.storage.get_signals(limit=1000, is_failing=True)), 10)
        self.assertEqual(len(self.storage.get_signals(limit=1000, is_failing=False)), 0)
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, sent=False, is_failing=False)), 0
        )
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=False)), 0
        )
        self.assertEqual(
            len(self.storage.get_signals(limit=1000, sent=True, is_failing=True)), 0
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
        self.assertEqual(1, MachineDBModel.objects.count())

        retrieved = self.storage.get_machine_by_id("1")

        self.assertEqual(retrieved.machine_id, m2.machine_id)
        self.assertEqual(retrieved.token, m2.token)
        self.assertEqual(retrieved.password, m2.password)
        self.assertEqual(retrieved.scenarios, m2.scenarios)

    def test_create_signal(self):
        self.assertEqual(self.storage.get_signals(limit=1000), [])
        self.storage.update_or_create_signal(mock_signals()[0])
        signals = self.storage.get_signals(limit=1000)
        self.assertEqual(len(signals), 1)
        signal = signals[0]

        self.assertIsNotNone(signal.alert_id)
        self.assertFalse(signal.sent)

        self.assertEqual(SignalDBModel.objects.count(), 1)
        self.assertEqual(len(signal.context), 4)

        self.assertEqual(len(signal.decisions), 1)

        self.assertTrue(isinstance(signal.source, SourceModel))

    def test_update_signal(self):
        self.assertEqual(self.storage.get_signals(limit=1000), [])

        to_insert = mock_signals()[0]
        self.storage.update_or_create_signal(to_insert)
        signals = self.storage.get_signals(limit=1000)

        self.assertEqual(len(signals), 1)
        signal = signals[0]

        self.assertFalse(signal.sent)

        signal.sent = True

        self.storage.update_or_create_signal(signal)
        signals = self.storage.get_signals(limit=1000)

        self.assertEqual(len(signals), 1)
        signal = signals[0]

        self.assertTrue(signal.sent)

    def test_mass_update_signals(self):
        self.assertEqual(self.storage.get_signals(limit=1000), [])

        for x in range(10):
            self.storage.update_or_create_signal(mock_signals()[0])

        signals = self.storage.get_signals(limit=1000)

        self.assertEqual(len(signals), 10)
        for s in signals:
            self.assertFalse(s.sent)
            self.assertEqual(s.scenario_trust, "trusted")
        signal_ids = [s.alert_id for s in signals]
        self.storage.mass_update_signals(
            signal_ids, {"sent": True, "scenario_trust": "manual"}
        )

        signals = self.storage.get_signals(limit=1000)

        self.assertEqual(len(signals), 10)
        for s in signals:
            self.assertTrue(s.sent)
            self.assertEqual(s.scenario_trust, "manual")
