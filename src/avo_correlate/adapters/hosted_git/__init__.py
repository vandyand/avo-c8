"""Hosted Git providers."""

from .c8_snapshot import C8GitHubSnapshotAdapter, C8SnapshotUnverifiable, GitHubC8SnapshotAdapter
from .campaign import GitHubCampaignProvider
from .github import (
    GitHubEvidenceSnapshot,
    GitHubIntegrationProvider,
    GitHubProtectionPolicy,
    GitHubProvider,
    GitHubPullRequestBinding,
    GitHubPullRequestDiscovery,
    GitHubRefObservation,
    GitHubRESTProvider,
    GitHubRollbackTopology,
    github_repository_digest,
)
from .github_transport import GitHubJsonTransport
from .protected_main import (
    MainGraduationAttester,
    MainMergeGroupObservation,
    MainProtectedProvider,
    MainPullRequestObservation,
    MainRefObservation,
    MainRepositoryObservation,
    ProtectedMainAttestationAdapter,
    ProtectedMainAttester,
    ProtectedMainGitHubProvider,
    ProtectedMainProvider,
    ProtectedMainProviderError,
    ProtectedMainRejected,
    ProtectedMainSnapshot,
)

__all__ = [
    "C8GitHubSnapshotAdapter",
    "C8SnapshotUnverifiable",
    "GitHubC8SnapshotAdapter",
    "GitHubCampaignProvider",
    "GitHubEvidenceSnapshot",
    "GitHubIntegrationProvider",
    "GitHubJsonTransport",
    "GitHubProtectionPolicy",
    "GitHubProvider",
    "GitHubPullRequestBinding",
    "GitHubPullRequestDiscovery",
    "GitHubRESTProvider",
    "GitHubRefObservation",
    "GitHubRollbackTopology",
    "MainGraduationAttester",
    "MainMergeGroupObservation",
    "MainProtectedProvider",
    "MainPullRequestObservation",
    "MainRefObservation",
    "MainRepositoryObservation",
    "ProtectedMainAttestationAdapter",
    "ProtectedMainAttester",
    "ProtectedMainGitHubProvider",
    "ProtectedMainProvider",
    "ProtectedMainProviderError",
    "ProtectedMainRejected",
    "ProtectedMainSnapshot",
    "github_repository_digest",
]
