from dataclasses import asdict
from typing import List, Optional

from dacite import from_dict
from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    TEXT,
    String,
    create_engine,
    delete,
    update,
    event,
    or_,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
    joinedload,
    selectinload,
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
    machine_id = Column(String(128), unique=True)
    token = Column(TEXT)
    password = Column(TEXT)
    scenarios = Column(TEXT)
    is_failing = Column(Boolean, default=False)


class DecisionDBModel(Base):
    __tablename__ = "decision_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    duration = Column(TEXT)
    uuid = Column(TEXT)
    scenario = Column(TEXT)
    origin = Column(TEXT)
    scope = Column(TEXT)
    simulated = Column(Boolean)
    until = Column(TEXT)
    type = Column(TEXT)
    value = Column(TEXT)
    signal_id: Mapped[int] = mapped_column(
        "signal_id", ForeignKey("signal_models.alert_id", ondelete="CASCADE")
    )


class SourceDBModel(Base):
    __tablename__ = "source_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scope = Column(TEXT)
    ip = Column(TEXT)
    latitude = Column(Float)
    as_number = Column(TEXT)
    range = Column(TEXT)
    cn = Column(TEXT)
    value = Column(TEXT)
    as_name = Column(TEXT)
    longitude = Column(Float)
    signal_id = Column(
        Integer, ForeignKey("signal_models.alert_id", ondelete="CASCADE")
    )


class ContextDBModel(Base):
    __tablename__ = "context_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(TEXT)
    key = Column(TEXT)
    signal_id: Mapped[int] = mapped_column(
        "signal_id", ForeignKey("signal_models.alert_id", ondelete="CASCADE")
    )


class SignalDBModel(Base):
    __tablename__ = "signal_models"

    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(TEXT)
    machine_id = Column(String(128))
    scenario_version = Column(TEXT, nullable=True)
    message = Column(TEXT, nullable=True)
    uuid = Column(TEXT)
    start_at = Column(TEXT, nullable=True)
    scenario_trust = Column(TEXT, nullable=True)
    scenario_hash = Column(TEXT, nullable=True)
    scenario = Column(TEXT, nullable=True)
    stop_at = Column(TEXT, nullable=True)
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
        self.session = sessionmaker(bind=engine)

    def get_signals(
        self,
        limit: int,
        offset: int = 0,
        sent: Optional[bool] = None,
        is_failing: Optional[bool] = None,
    ) -> List[storage.SignalModel]:
        with self.session.begin() as session:
            query = session.query(SignalDBModel).options(
                selectinload("*"),
                joinedload(SignalDBModel.source),
            )
            if sent is not None:
                if sent:
                    query = query.filter(SignalDBModel.sent == True)
                else:
                    query = query.filter(
                        or_(SignalDBModel.sent.is_(False), SignalDBModel.sent == None)
                    )

            if is_failing is not None:
                query = query.outerjoin(
                    MachineDBModel,
                    MachineDBModel.machine_id == SignalDBModel.machine_id,
                )
                if is_failing:
                    query = query.filter(MachineDBModel.is_failing == True)
                else:
                    query = query.filter(
                        or_(
                            MachineDBModel.is_failing == False,
                            MachineDBModel.is_failing == None,
                        )
                    )

            query = query.limit(limit).offset(offset)
            results = query.all()
            return [from_dict(storage.SignalModel, res.to_dict()) for res in results]

    def get_machine_by_id(self, machine_id: str) -> Optional[storage.MachineModel]:
        with self.session.begin() as session:
            existing = (
                session.query(MachineDBModel)
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
        with self.session.begin() as session:
            existing = (
                session.query(MachineDBModel)
                .filter(MachineDBModel.machine_id == machine.machine_id)
                .all()
            )
            if not existing:
                session.add(MachineDBModel(**asdict(machine)))
                return True

            update_stmt = (
                update(MachineDBModel)
                .where(MachineDBModel.machine_id == machine.machine_id)
                .values(**asdict(machine))
            )
            session.execute(update_stmt)
        return False

    def mass_update_signals(self, signal_ids: List[int], changes: dict):
        with self.session.begin() as session:
            stmt = update(SignalDBModel).where(SignalDBModel.alert_id.in_(signal_ids))
            stmt = stmt.values(changes)
            session.execute(stmt)

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
        with self.session.begin() as session:
            existing = (
                session.query(SignalDBModel)
                .filter(SignalDBModel.alert_id == signal.alert_id)
                .first()
            )

            if not existing:
                session.add(to_insert)
                return True

            for c in to_insert.__table__.columns:
                setattr(existing, c.name, getattr(to_insert, c.name))

        return False

    def delete_signals(self, signal_ids: List[int]):
        stmt = delete(SignalDBModel).where(SignalDBModel.alert_id.in_(signal_ids))
        with self.session.begin() as session:
            session.execute(stmt)

    def delete_machines(self, machine_ids: List[str]):
        stmt = delete(MachineDBModel).where(MachineDBModel.machine_id.in_(machine_ids))
        with self.session.begin() as session:
            session.execute(stmt)
