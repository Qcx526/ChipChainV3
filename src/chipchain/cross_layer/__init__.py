"""Typed cross-layer contracts and compatibility exports."""
from .contracts import (
    CrossLayerAtomMatch, CrossLayerTriggerCandidate, FirmwareAtomBinding, FirmwareCrossLayerFactRef,
    cross_layer_candidate_sha256, parse_cross_layer_candidate, serialize_cross_layer_candidate,
)
from .eligibility import (
    CrossLayerPairDescriptor, CrossLayerPairManifest, build_cross_layer_pair,
    cross_layer_pair_sha256, parse_cross_layer_pair, serialize_cross_layer_pair,
)
from .facts import FirmwareFactSources
from .matcher import PairNotEligible, match_trigger_condition, revalidate_candidate
from .trigger import (
    HardwareTriggerCondition, HardwareTriggerConditionInput, build_hardware_trigger_condition,
    hardware_trigger_condition_sha256, parse_hardware_trigger_condition, serialize_hardware_trigger_condition,
)

__all__ = [
    'CrossLayerAtomMatch', 'CrossLayerTriggerCandidate', 'FirmwareAtomBinding', 'FirmwareCrossLayerFactRef',
    'CrossLayerPairDescriptor', 'CrossLayerPairManifest', 'build_cross_layer_pair', 'FirmwareFactSources',
    'PairNotEligible', 'match_trigger_condition', 'revalidate_candidate', 'HardwareTriggerCondition',
    'HardwareTriggerConditionInput', 'build_hardware_trigger_condition', 'cross_layer_candidate_sha256',
    'parse_cross_layer_candidate', 'serialize_cross_layer_candidate', 'cross_layer_pair_sha256',
    'parse_cross_layer_pair', 'serialize_cross_layer_pair', 'hardware_trigger_condition_sha256',
    'parse_hardware_trigger_condition', 'serialize_hardware_trigger_condition',
]
