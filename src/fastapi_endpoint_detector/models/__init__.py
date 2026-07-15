"""
Data models for FastAPI Endpoint Change Detector.

This package contains Pydantic models for representing endpoints,
dependencies, diff changes, and analysis reports.
"""

from fastapi_endpoint_detector.models.dependency import (
    Dependency,
    DependencyType,
    ModuleInfo,
)
from fastapi_endpoint_detector.models.diff import (
    ChangeType,
    DiffFile,
    DiffHunk,
    FileChange,
)
from fastapi_endpoint_detector.models.effect_contract import (
    EffectContract,
    EffectContractDocument,
    EffectContractError,
    LoadedEffectContracts,
    ResolvedCallSite,
    load_effect_contracts,
    load_effect_preset,
)
from fastapi_endpoint_detector.models.effect_contract_audit import (
    AuditCallStatus,
    AuditEndpoint,
    AuditLimitation,
    EffectContractAudit,
    EffectContractAuditError,
    EffectContractAuditOccurrence,
    EffectContractAuditProvenance,
    EffectContractAuditScope,
    EffectContractAuditSummary,
    EffectContractCoverage,
)
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
    SurfaceRegistrationEvidence,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    ChangeEffectKind,
    CodeReference,
    ConfidenceLevel,
    ContractEffectEvidence,
    DataObservationKind,
    EffectDisposition,
    EffectEvidence,
    EvidenceProducer,
    EvidenceStatus,
    ImpactChannel,
)
from fastapi_endpoint_detector.models.surface_contract import (
    CallbackMode,
    HandlerNameNormalization,
    LoadedSurfaceContracts,
    SurfaceContract,
    SurfaceContractDocument,
    SurfaceContractError,
    SurfaceExecutionMode,
    load_surface_contracts,
    load_surface_preset,
)

__all__ = [  # noqa: RUF022 - grouped by public model domain
    # Endpoint models
    "Endpoint",
    "EndpointDiscoveryCondition",
    "EndpointDiscoveryStatus",
    "EndpointInventory",
    "EndpointMethod",
    "HandlerInfo",
    "InventoryStatus",
    "SurfaceRegistrationEvidence",
    # Dependency models
    "Dependency",
    "DependencyType",
    "ModuleInfo",
    # Diff models
    "DiffFile",
    "DiffHunk",
    "FileChange",
    "ChangeType",
    # Effect contract models
    "EffectContract",
    "EffectContractDocument",
    "EffectContractError",
    "LoadedEffectContracts",
    "ResolvedCallSite",
    "load_effect_contracts",
    "load_effect_preset",
    # Custom surface contract models
    "CallbackMode",
    "HandlerNameNormalization",
    "LoadedSurfaceContracts",
    "SurfaceContract",
    "SurfaceContractDocument",
    "SurfaceContractError",
    "SurfaceExecutionMode",
    "load_surface_contracts",
    "load_surface_preset",
    # Effect contract audit models
    "AuditCallStatus",
    "AuditEndpoint",
    "AuditLimitation",
    "EffectContractAudit",
    "EffectContractAuditError",
    "EffectContractAuditOccurrence",
    "EffectContractAuditProvenance",
    "EffectContractAuditScope",
    "EffectContractAuditSummary",
    "EffectContractCoverage",
    # Report models
    "AffectedEndpoint",
    "AnalysisReport",
    "ChangeEffectKind",
    "CodeReference",
    "ConfidenceLevel",
    "ContractEffectEvidence",
    "DataObservationKind",
    "EffectDisposition",
    "EffectEvidence",
    "EvidenceProducer",
    "EvidenceStatus",
    "ImpactChannel",
]
