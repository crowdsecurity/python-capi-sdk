from dataclasses import asdict
from typing import List

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
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from cscapi import storage


class Base(DeclarativeBase):
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class MachineDBModel(Base):
    __tablename__ = "machine_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    machine_id = Column(String)
    token = Column(String)
    password = Column(String)
    scenarios = Column(String)


class DecisionDBModel(Base):
    __tablename__ = "decision_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    duration = Column(String)
    uuid = Column(String)
    scenario = Column(String)
    origin = Column(String)
    scope = Column(String)
    simulated = Column(Boolean)
    until = Column(String)
    type = Column(String)
    value = Column(String)
    signal_id: Mapped[int] = mapped_column(
        "signal_id", ForeignKey("signal_models.alert_id")
    )


class SourceDBModel(Base):
    __tablename__ = "source_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scope = Column(String)
    ip = Column(String)
    latitude = Column(Float)
    as_number = Column(String)
    range = Column(String)
    cn = Column(String)
    value = Column(String)
    as_name = Column(String)
    longitude = Column(Float)


class ContextDBModel(Base):
    __tablename__ = "context_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String)
    key = Column(String)
    signal_id: Mapped[int] = mapped_column(
        "signal_id", ForeignKey("signal_models.alert_id")
    )


class SignalDBModel(Base):
    __tablename__ = "signal_models"

    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(String)
    machine_id = Column(String)
    scenario_version = Column(String, nullable=True)
    message = Column(String, nullable=True)
    uuid = Column(String)
    start_at = Column(String, nullable=True)
    scenario_trust = Column(String, nullable=True)
    scenario_hash = Column(String, nullable=True)
    scenario = Column(String, nullable=True)
    stop_at = Column(String, nullable=True)
    sent = Column(Boolean, default=False)

    source_id = Column(Integer, ForeignKey("source_models.id"), nullable=True)

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

    def get_machine_by_id(self, machine_id: str) -> storage.MachineModel:
        exisiting = (
            self.session.query(MachineDBModel)
            .filter(MachineDBModel.machine_id == machine_id)
            .first()
        )
        if not exisiting:
            return
        return MachineDBModel(
            machine_id=exisiting.machine_id,
            token=exisiting.token,
            password=exisiting.password,
            scenarios=exisiting.scenarios,
        )

    def update_or_create_machine(self, machine: storage.MachineModel) -> bool:
        exisiting = (
            self.session.query(MachineDBModel)
            .filter(MachineDBModel.machine_id == machine.machine_id)
            .all()
        )
        if not exisiting:
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

        exisiting = (
            self.session.query(SignalDBModel)
            .filter(SignalDBModel.alert_id == signal.alert_id)
            .first()
        )
        if not exisiting:
            self.session.add(to_insert)
            self.session.commit()
            return True

        for c in to_insert.__table__.columns:
            setattr(exisiting, c.name, getattr(to_insert, c.name))
        self.session.commit()
        return False

    def delete_signals(self, signals: List[storage.SignalModel]):
        stmt = delete(SignalDBModel).where(
            SignalDBModel.alert_id in ([signal.alert_id for signal in signals])
        )
        self.session.execute(stmt)

    def delete_machines(self, machines: List[storage.MachineModel]):
        stmt = delete(MachineDBModel).where(
            MachineDBModel.machine_id in ([machine.machine_id for machine in machines])
        )
        self.session.execute(stmt)
