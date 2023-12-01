import os
import time
from unittest import TestCase

from cscapi.sql_storage import (
    ContextDBModel,
    DecisionDBModel,
    MachineDBModel,
    SignalDBModel,
    SourceDBModel,
    SQLStorage,
)
from cscapi.storage import MachineModel, SourceModel

from .test_client import mock_signals


class TestSQLStorage(TestCase):
    def setUp(self) -> None:
        self.db_path = f"{str(int(time.time()))}.db"
        db_uri = f"sqlite:///{self.db_path}"
        self.storage: SQLStorage = SQLStorage(db_uri)

    def tearDown(self) -> None:
        try:
            os.remove(self.db_path)
        except:
            pass

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
        self.assertEqual(1, self.storage.session.query(MachineDBModel).count())

        retrieved = self.storage.get_machine_by_id("1")

        self.assertEqual(retrieved.machine_id, m2.machine_id)
        self.assertEqual(retrieved.token, m2.token)
        self.assertEqual(retrieved.password, m2.password)
        self.assertEqual(retrieved.scenarios, m2.scenarios)

    def test_create_signal(self):
        assert self.storage.get_all_signals() == []
        self.storage.update_or_create_signal(mock_signals()[0])
        signals = self.storage.get_all_signals()
        assert len(signals) == 1
        signal = signals[0]

        assert signal.alert_id is not None
        assert signal.sent == False

        assert self.storage.session.query(ContextDBModel).count() == 4
        assert len(signal.context) == 4

        assert self.storage.session.query(DecisionDBModel).count() == 1
        assert len(signal.decisions) == 1

        assert isinstance(signal.source, SourceModel)
        assert self.storage.session.query(SourceDBModel).count() == 1

    def test_update_signal(self):
        assert self.storage.get_all_signals() == []

        to_insert = mock_signals()[0]
        self.storage.update_or_create_signal(to_insert)
        signals = self.storage.get_all_signals()

        assert len(signals) == 1
        signal = signals[0]

        assert signal.sent == False

        signal.sent = True

        self.storage.update_or_create_signal(signal)
        signals = self.storage.get_all_signals()

        assert len(signals) == 1
        signal = signals[0]

        assert signal.sent == True
