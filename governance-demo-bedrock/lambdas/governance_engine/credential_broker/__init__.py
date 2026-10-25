"""Provider-neutral credential broker for delegated authority grants.

The governance model is vendor-neutral; the enforcement mechanism is
provider-native. Every adapter implements the same contract:
verified grant -> provider credential no broader than the grant -> execution.
"""

from .aws_adapter import AwsStsAdapter, build_session_policy, resource_arn_for
from .base import (
    MODE_LIVE,
    MODE_MOCK,
    BrokerRefusal,
    CredentialHandle,
    CredentialProvider,
    ExecutionResult,
    ProviderNotConfigured,
)
from .broker import CredentialBroker
from .entra_adapter import EntraAdapter
from .google_adapter import GoogleAdapter
from .governance_adapter import GovernanceAdapter, oversight_table_definition
from .mock_adapter import MockProvider
from .servicenow_adapter import ServiceNowAdapter

__all__ = [
    "MODE_LIVE", "MODE_MOCK", "AwsStsAdapter", "BrokerRefusal", "CredentialBroker",
    "CredentialHandle", "CredentialProvider", "EntraAdapter", "ExecutionResult",
    "GoogleAdapter", "GovernanceAdapter", "MockProvider", "ProviderNotConfigured",
    "ServiceNowAdapter", "build_session_policy", "oversight_table_definition", "resource_arn_for",
]
