"""Unified Engineering Intelligence subsystem for LogicFalcon."""

from packages.review.unified.engine import UnifiedIntelligenceEngine
from packages.review.unified.models import (
    RecommendationCategory,
    RecommendationPriority,
    UnifiedIntelligenceReport,
    UnifiedRecommendation,
)
from packages.review.unified.recommendations import RecommendationSynthesizer
from packages.review.unified.report_generator import UnifiedReportGenerator

__all__ = [
    "RecommendationCategory",
    "RecommendationPriority",
    "RecommendationSynthesizer",
    "UnifiedIntelligenceEngine",
    "UnifiedIntelligenceReport",
    "UnifiedRecommendation",
    "UnifiedReportGenerator",
]
