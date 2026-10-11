"""Provider-neutral contracts. No Firebase SDK objects cross this boundary."""
from dataclasses import dataclass, field, asdict
from enum import StrEnum
from typing import Any

class ProviderState(StrEnum):
    NOT_CONFIGURED='NOT_CONFIGURED'; READY='READY'; UNAVAILABLE='UNAVAILABLE'; DEGRADED='DEGRADED'
class DynamicJobStatus(StrEnum):
    PENDING='PENDING'; UPLOADING='UPLOADING'; QUEUED='QUEUED'; RUNNING='RUNNING'; COLLECTING='COLLECTING'
    COMPLETED='COMPLETED'; FAILED='FAILED'; INCONCLUSIVE='INCONCLUSIVE'; CANCELLED='CANCELLED'; TIMED_OUT='TIMED_OUT'; NOT_RUN='NOT_RUN'
TERMINAL={DynamicJobStatus.COMPLETED,DynamicJobStatus.FAILED,DynamicJobStatus.INCONCLUSIVE,DynamicJobStatus.CANCELLED,DynamicJobStatus.TIMED_OUT,DynamicJobStatus.NOT_RUN}
class ArtifactStatus(StrEnum):
    AVAILABLE='AVAILABLE'; MISSING='MISSING'; FAILED_TO_FETCH='FAILED_TO_FETCH'; NOT_SUPPORTED='NOT_SUPPORTED'
@dataclass
class DynamicError(Exception):
    code: str
    message: str
    def __str__(self): return self.message
@dataclass
class DynamicProviderStatus:
    provider: str
    status: ProviderState
    checks: dict[str,bool] = field(default_factory=dict)
    error: DynamicError | None = None
    devices: list[dict[str,Any]] = field(default_factory=list)
    quota_status: str = 'UNKNOWN'
    enabled: bool = False
    timeout_seconds: int = 300
@dataclass
class DynamicRequest:
    scan_id: str
    apk_path: str
    workspace: str
    sha256: str
    metadata: dict[str,Any]
    confirm_cloud_upload: bool = False
    job_id: str = ''
@dataclass
class DynamicJob:
    id: str
    scan_id: str
    provider: str
    status: DynamicJobStatus = DynamicJobStatus.PENDING
    remote_job_id: str | None = None
    device: dict[str,Any] = field(default_factory=dict)
    created_at: float = 0
    started_at: float | None = None
    completed_at: float | None = None
    provider_result_url: str | None = None
    uploaded_sha256: str = ''
    stage: str = 'Preparing APK'
    error: DynamicError | None = None
    audit: dict[str,Any] = field(default_factory=dict)
    events: list[dict[str,Any]] = field(default_factory=list)
@dataclass
class DynamicArtifact:
    id: str
    type: str
    remote_uri: str | None = None
    local_path: str | None = None
    status: ArtifactStatus = ArtifactStatus.MISSING
    size: int | None = None
    content_type: str | None = None
    evidence_source: str = ''
@dataclass
class DynamicObservation:
    id: str
    type: str
    summary: str
    timestamp: str | None = None
    evidence_source: str = ''
    source_label: str = ''
    attributes: dict[str,Any] = field(default_factory=dict)
    artifact_ids: list[str] = field(default_factory=list)
@dataclass
class DynamicResult:
    provider: str
    job_id: str
    status: DynamicJobStatus
    started_at: float | None = None
    finished_at: float | None = None
    device: dict[str,Any] = field(default_factory=dict)
    test_type: str = 'robo'
    artifacts: list[DynamicArtifact] = field(default_factory=list)
    observations: list[DynamicObservation] = field(default_factory=list)
    provider_metadata: dict[str,Any] = field(default_factory=dict)
    analysis_gaps: list[str] = field(default_factory=list)
    coverage: str = 'LIMITED'

    def __post_init__(self):
        if self.status == DynamicJobStatus.NOT_RUN:
            self.coverage = 'NOT_RUN'

def serial(value):
    return asdict(value)
