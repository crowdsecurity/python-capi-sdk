from dataclasses import asdict
from typing import List, Optional

from dacite import from_dict
from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    String,
    create_engine,
    delete,
    update,
    event,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from sqlalchemy.engine import Engine
from sqlite3 import Connection as SQLiteConnection
from cscapi import storage


"""
By default, foreign key constraints are disabled in SQLite.
@see https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#foreign-key-support
"""


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, SQLiteConnection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class Base(DeclarativeBase):
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class MachineDBModel(Base):
    __tablename__ = "machine_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    machine_id = Column(String(512), unique=True)
    token = Column(String(512))
    password = Column(String(512))
    scenarios = Column(String(512))
    is_failing = Column(Boolean, default=False)


class DecisionDBModel(Base):
    __tablename__ = "decision_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    duration = Column(String(512))
    uuid = Column(String(512))
    scenario = Column(String(512))
    origin = Column(String(512))
    scope = Column(String(512))
    simulated = Column(Boolean)
    until = Column(String(512))
    type = Column(String(512))
    value = Column(String(512))
    signal_id: Mapped[int] = mapped_column(
        "signal_id", ForeignKey("signal_models.alert_id", ondelete="CASCADE")
    )


class SourceDBModel(Base):
    __tablename__ = "source_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scope = Column(String(512))
    ip = Column(String(512))
    latitude = Column(Float)
    as_number = Column(String(512))
    range = Column(String(512))
    cn = Column(String(512))
    value = Column(String(512))
    as_name = Column(String(512))
    longitude = Column(Float)
    signal_id = Column(
        Integer, ForeignKey("signal_models.alert_id", ondelete="CASCADE")
    )


class ContextDBModel(Base):
    __tablename__ = "context_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(512))
    key = Column(String(512))
    signal_id: Mapped[int] = mapped_column(
        "signal_id", ForeignKey("signal_models.alert_id", ondelete="CASCADE")
    )


class SignalDBModel(Base):
    __tablename__ = "signal_models"

    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(String(512))
    machine_id = Column(String(512))
    scenario_version = Column(String(512), nullable=True)
    message = Column(String(512), nullable=True)
    uuid = Column(String(512))
    start_at = Column(String(512), nullable=True)
    scenario_trust = Column(String(512), nullable=True)
    scenario_hash = Column(String(512), nullable=True)
    scenario = Column(String(512), nullable=True)
    stop_at = Column(String(512), nullable=True)
    sent = Column(Boolean, default=False)

    context: Mapped[List["ContextDBModel"]] = relationship(
        "ContextDBModel", backref="signal"
    )
    decisions: Mapped[List["DecisionDBModel"]] = relationship(
        "DecisionDBModel", backref="signal"
    )
    source = relationship("SourceDBModel", uselist=False, backref="signal")

    def to_dict(self):
        d = super().to_dict()
        d["source"] = self.source.to_dict() if self.source else {}
        d["context"] = [ctx.to_dict() for ctx in self.context] if self.context else []
        d["decisions"] = (
            [dec.to_dict() for dec in self.decisions] if self.decisions else []
        )
        return d


class SQLStorage(storage.StorageInterface):
    def __init__(self, connection_string="sqlite:///cscapi.db") -> None:
        engine = create_engine(connection_string, echo=False)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.session = Session()

    def get_all_signals(self) -> List[storage.SignalModel]:
        return [
            from_dict(storage.SignalModel, res.to_dict())
            for res in self.session.query(SignalDBModel).all()
        ]

    def get_machine_by_id(self, machine_id: str) -> Optional[storage.MachineModel]:
        existing = (
            self.session.query(MachineDBModel)
            .filter(MachineDBModel.machine_id == machine_id)
            .first()
        )
        if not existing:
            return None
        return storage.MachineModel(
            machine_id=existing.machine_id,
            token=existing.token,
            password=existing.password,
            scenarios=existing.scenarios,
            is_failing=existing.is_failing,
        )

    def update_or_create_machine(self, machine: storage.MachineModel) -> bool:
        existing = (
            self.session.query(MachineDBModel)
            .filter(MachineDBModel.machine_id == machine.machine_id)
            .all()
        )
        if not existing:
            self.session.add(MachineDBModel(**asdict(machine)))
            self.session.commit()
            return True

        update_stmt = (
            update(MachineDBModel)
            .where(MachineDBModel.machine_id == machine.machine_id)
            .values(**asdict(machine))
        )
        self.session.execute(update_stmt)
        self.session.commit()
        return False

    def update_or_create_signal(self, signal: storage.SignalModel) -> bool:
        to_insert = SignalDBModel(
            **{
                k: v
                for k, v in asdict(signal).items()
                if k != "source" and k != "context" and k != "decisions"
            }
        )

        if signal.source:
            to_insert.source = SourceDBModel(**asdict(signal.source))

        if signal.context:
            to_insert.context = [
                ContextDBModel(**{"signal_id": to_insert.alert_id} | asdict(ctx))
                for ctx in signal.context
            ]

        if signal.decisions:
            to_insert.decisions = [
                DecisionDBModel(**{"signal_id": to_insert.alert_id} | asdict(dec))
                for dec in signal.decisions
            ]

        existing = (
            self.session.query(SignalDBModel)
            .filter(SignalDBModel.alert_id == signal.alert_id)
            .first()
        )

        if not existing:
            self.session.add(to_insert)
            self.session.commit()
            return True

        for c in to_insert.__table__.columns:
            setattr(existing, c.name, getattr(to_insert, c.name))

        self.session.commit()
        return False

    def delete_signals(self, signals: List[storage.SignalModel]):
        stmt = delete(SignalDBModel).where(
            SignalDBModel.alert_id.in_((signal.alert_id for signal in signals))
        )
        self.session.execute(stmt)
        self.session.commit()

    def delete_machines(self, machines: List[storage.MachineModel]):
        stmt = delete(MachineDBModel).where(
            MachineDBModel.machine_id.in_((machine.machine_id for machine in machines))
        )
        self.session.execute(stmt)
        self.session.commit()
