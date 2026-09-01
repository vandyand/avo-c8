"""Hosted Git providers."""

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
from .github_transport import GitHubJsonTransport

__all__ = [
    "GitHubCampaignProvider",
    "GitHubJsonTransport",
    "GitHubEvidenceSnapshot",
    "GitHubIntegrationProvider",
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
