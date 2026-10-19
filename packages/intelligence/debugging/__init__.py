"""AEGIS AI Phase 3: Autonomous Debugging & Evidence-Grounded Reasoning."""

from packages.intelligence.debugging.analyzer import RootCauseAnalyzer
from packages.intelligence.debugging.collector import DebuggingEvidenceCollector
from packages.intelligence.debugging.localizer import FailureLocalizer
from packages.intelligence.debugging.models import (
    DebuggingAnalysisRun,
    DebuggingAnalysisStatus,
    DebuggingEvidenceItem,
    DebuggingIncidentInput,
    EvidenceRelevanceLevel,
    FixProposal,
    FixValidationStatus,
    FrameOriginType,
    HypothesisVerdict,
    IncidentFrameInput,
    NormalizedDebuggingIncident,
    RankedHypothesis,
    StackTraceFrame,
    VerificationStatus,
    VerificationStep,
    redact_sensitive_content,
)
from packages.intelligence.debugging.normalizer import IncidentNormalizer
from packages.intelligence.debugging.remediation_proposals import (
    FixProposalService,
    FixValidationService,
)
from packages.intelligence.debugging.service import AutonomousDebuggingService
from packages.intelligence.debugging.stack_parser import StackTraceParser
from packages.intelligence.debugging.verification import VerificationPlanner

__all__ = [
    "AutonomousDebuggingService",
    "DebuggingAnalysisRun",
    "DebuggingAnalysisStatus",
    "DebuggingEvidenceCollector",
    "DebuggingEvidenceItem",
    "DebuggingIncidentInput",
    "EvidenceRelevanceLevel",
    "FailureLocalizer",
    "FixProposal",
    "FixProposalService",
    "FixValidationService",
    "FixValidationStatus",
    "FrameOriginType",
    "HypothesisVerdict",
    "IncidentFrameInput",
    "IncidentNormalizer",
    "NormalizedDebuggingIncident",
    "RankedHypothesis",
    "RootCauseAnalyzer",
    "StackTraceFrame",
    "StackTraceParser",
    "VerificationPlanner",
    "VerificationStatus",
    "VerificationStep",
    "redact_sensitive_content",
]
