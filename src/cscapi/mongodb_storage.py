import logging
from dataclasses import asdict
from typing import List, Optional

from dacite import from_dict
from mongoengine import (
    ConnectionFailure,
    Document,
    EmbeddedDocument,
    Q,
    connect,
    fields,
)

from cscapi.storage import MachineModel, SignalModel, StorageInterface

logger = logging.getLogger(__name__)


class ContextDBModel(EmbeddedDocument):
    value = fields.StringField()
    key = fields.StringField()


class DecisionDBModel(EmbeddedDocument):
    duration = fields.StringField()
    uuid = fields.StringField()
    scenario = fields.StringField()
    origin = fields.StringField()
    scope = fields.StringField()
    simulated = fields.BooleanField()
    until = fields.StringField()
    type = fields.StringField()
    value = fields.StringField()


class SourceDBModel(EmbeddedDocument):
    scope = fields.StringField()
    ip = fields.StringField()
    latitude = fields.FloatField()
    as_number = fields.StringField()
    range = fields.StringField()
    cn = fields.StringField()
    value = fields.StringField()
    as_name = fields.StringField()
    longitude = fields.FloatField()


class SignalDBModel(Document):
    alert_id = fields.SequenceField(unique=True)
    created_at = fields.StringField()
    machine_id = fields.StringField(max_length=128)
    scenario_version = fields.StringField(null=True)
    message = fields.StringField(null=True)
    uuid = fields.StringField()
    start_at = fields.StringField(null=True)
    scenario_trust = fields.StringField(null=True)
    scenario_hash = fields.StringField(null=True)
    scenario = fields.StringField(null=True)
    stop_at = fields.StringField(null=True)
    sent = fields.BooleanField(default=False)
    context = fields.EmbeddedDocumentListField(ContextDBModel)
    decisions = fields.EmbeddedDocumentListField(DecisionDBModel)
    source = fields.EmbeddedDocumentField(SourceDBModel)

    meta = {"collection": "signal_models"}


class MachineDBModel(Document):
    machine_id = fields.StringField(max_length=128, unique=True)
    token = fields.StringField()
    password = fields.StringField()
    scenarios = fields.StringField()
    is_failing = fields.BooleanField(default=False)

    meta = {"collection": "machine_models"}


class MongoDBStorage(StorageInterface):
    def __init__(self, connection_string="mongodb://127.0.0.1:27017/cscapi"):
        try:
            connect(
                host="mongodb://127.0.0.1:27017/cscapi",
                connect=False,
                uuidRepresentation="standard",
            )
        except ConnectionFailure:
            logger.info(
                "There is already an existing connection to MongoDB. Using that as default."
            )

    def mass_update_signals(self, signal_ids: List[int], changes: dict):
        SignalDBModel.objects.filter(alert_id__in=signal_ids).update(**changes)

    def get_signals(
        self,
        limit: int,
        offset: int = 0,
        sent: Optional[bool] = None,
        is_failing: Optional[bool] = None,
    ) -> List[SignalModel]:
        join_name = "joined"
        filter_sent = Q()
        filter_is_failing = {}

        if sent is not None:
            if sent:
                filter_sent = Q(sent=True)
            else:
                filter_sent = Q(sent=False) | Q(sent=None)

        if is_failing is not None:
            if is_failing:
                filter_is_failing = {"$match": {"is_failing": True}}
            else:
                filter_is_failing = {
                    "$match": {"$or": [{"is_failing": False}, {"is_failing": None}]}
                }

        pipeline = [
            {  # performs a left outer join and return an object called as join_name
                "$lookup": {
                    "from": MachineDBModel._get_collection_name(),
                    "localField": "machine_id",
                    "foreignField": "machine_id",
                    "as": join_name,
                }
            },
            {  # if a machine isn't found, fill the value of is_failing with None at object root level
                # otherwise copy the value of the attribute from the matching machine to root level
                "$set": {
                    "is_failing": {
                        "$cond": {
                            "if": {"$eq": [{"$size": f"${join_name}"}, 0]},
                            "then": None,
                            "else": {"$arrayElemAt": [f"${join_name}.is_failing", 0]},
                        }
                    }
                }
            },
        ]
        if filter_is_failing:
            pipeline.append(filter_is_failing)
        pipeline.extend([{"$limit": limit + offset}, {"$skip": offset}])

        results = SignalDBModel.objects.filter(filter_sent).aggregate(pipeline)
        return [from_dict(SignalModel, res) for res in results]

    def get_machine_by_id(self, machine_id: str) -> Optional[MachineModel]:
        machine = MachineDBModel.objects.filter(machine_id=machine_id).first()
        return from_dict(MachineModel, machine) if machine else None

    def update_or_create_machine(self, machine: MachineModel) -> bool:
        try:
            result = MachineDBModel.objects.get(machine_id=machine.machine_id)
        except MachineDBModel.DoesNotExist:
            MachineDBModel.objects.create(**asdict(machine))
            return True
        else:
            result.update(**asdict(machine))
            return False

    def update_or_create_signal(self, signal: SignalModel) -> bool:
        # Filter out the keys for embedded documents to handle them separately
        signal_filtered = {
            k: v
            for k, v in asdict(signal).items()
            if k not in ["source", "context", "decisions"]
        }

        created = False  # Flag to track if a new document is created

        # Only proceed if alert_id is not None
        if signal.alert_id is not None:
            try:
                signal_db_model = SignalDBModel.objects.get(alert_id=signal.alert_id)
                logger.info(signal_filtered)
                signal_db_model.update(**signal_filtered)
            except SignalDBModel.DoesNotExist:
                # If it doesn't exist, create a new one with all the data including alert_id
                signal_db_model = SignalDBModel(**signal_filtered)
                created = True
        else:
            # If alert_id is None, directly create a new model with the provided data
            signal_db_model = SignalDBModel(**signal_filtered)
            created = True

        # Update or set the source, context, and decisions fields
        if signal.source:
            signal_db_model.source = SourceDBModel(**asdict(signal.source))

        if signal.context:
            signal_db_model.context = [
                ContextDBModel(**asdict(ctx)) for ctx in signal.context
            ]

        if signal.decisions:
            signal_db_model.decisions = [
                DecisionDBModel(**asdict(dec)) for dec in signal.decisions
            ]

        # Save the model (works for both creating a new document and updating an existing one)
        signal_db_model.save()

        return created

    def delete_signals(self, signal_ids: List[int]):
        SignalDBModel.objects.filter(alert_id__in=signal_ids).delete()

    def delete_machines(self, machine_ids: List[str]):
        MachineDBModel.objects.filter(machine_id__in=machine_ids).delete()
