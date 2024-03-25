import logging
from dataclasses import asdict
from typing import List, Optional

from dacite import from_dict
from mongoengine import Document, EmbeddedDocument, fields

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


class MachineDBModel(Document):
    machine_id = fields.StringField(max_length=128, unique=True)
    token = fields.StringField()
    password = fields.StringField()
    scenarios = fields.StringField()
    is_failing = fields.BooleanField(default=False)


class MongoDBStorage(StorageInterface):
    def mass_update_signals(self, signal_ids: List[int], changes: dict):
        SignalDBModel.objects.filter(alert_id__in=signal_ids).update(**changes)

    def get_signals(
        self,
        limit: int,
        offset: int = 0,
        sent: Optional[bool] = None,
        is_failing: Optional[bool] = None,
    ) -> List[SignalModel]:
        results: [SignalDBModel] = []  # handle results after first filter ("sent")
        final: [SignalDBModel] = []  # handle final results that will be returned
        join_name = "joined"
        with SignalDBModel.objects.aggregate(
            [
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
                                "else": {
                                    "$arrayElemAt": [f"${join_name}.is_failing", 0]
                                },
                            }
                        }
                    }
                },
            ]
        ) as join:
            for entry in join:
                # if "sent" parameter has not been set add everything
                if sent is not None:
                    if sent:
                        if entry["sent"] is True:
                            results.append(entry)
                        continue
                    else:
                        # value "false" can be False or None
                        if entry["sent"] is False or entry["sent"] is None:
                            results.append(entry)
                        continue
                results.append(entry)
            for entry in results:
                # if is_failing parameter has not been set add everything
                if is_failing is not None:
                    if is_failing:
                        if entry["is_failing"] is True:
                            final.append(entry)
                        continue
                    else:
                        # value "false" can be False or None
                        if entry["is_failing"] is False or entry["is_failing"] is None:
                            final.append(entry)
                        continue
                final.append(entry)
        return [from_dict(SignalModel, res) for res in final[offset : offset + limit]]

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
        signal_filtered = {
            k: v
            for k, v in asdict(signal).items()
            if k not in ["source", "context", "decisions"]
        }
        signal_db_model = SignalDBModel(**signal_filtered)

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

        try:
            # this if is necessary in order to make mongo
            # create a new object id when None is passed
            if not signal.alert_id:
                signal.alert_id = -1
            result = SignalDBModel.objects.get(alert_id=signal.alert_id)
        except SignalDBModel.DoesNotExist:
            signal_db_model.save()
            return True
        else:
            result.update(**asdict(signal))
            return False

    def delete_signals(self, signal_ids: List[int]):
        SignalDBModel.objects.filter(alert_id__in=signal_ids).delete()

    def delete_machines(self, machine_ids: List[str]):
        MachineDBModel.objects.filter(machine_id__in=machine_ids).delete()
