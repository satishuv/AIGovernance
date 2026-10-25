"""Authenticated caller identity for the governance planes.

Every governance decision about WHO is acting comes from the authenticated
request context, never from fields in the request body. A body may carry an
"approver_id" or "agent_id" for display, but it is either ignored or required
to match the authenticated principal.

Three planes, three kinds of caller:
  * agent plane      an AI agent asks to perform an operation
  * approval plane   a human approves or denies an escalated request
  * admin plane      a human governance administrator changes scope, revokes
                     authority or activates the kill switch

An IAM principal is an agent when its role is registered as an agent runtime
principal in the agent registry. Agents can never approve, administer, or
change their own authority, whatever roles are recorded for them.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# Roles (from the GovernanceRolesTable) that may approve an escalated request.
APPROVER_ROLES = frozenset({"policy_approver", "operator", "governance_admin"})
# Roles that may change an agent's scope or registry entry.
ADMIN_ROLES = frozenset({"governance_admin"})
# Roles that may revoke delegated authority or activate the kill switch.
REVOKER_ROLES = frozenset({"operator", "governance_admin"})

_ASSUMED_ROLE_RE = re.compile(r"^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role/([^/]+)/(.+)$")


def normalize_principal_arn(arn: str) -> str:
    """Map an STS assumed-role session ARN to its IAM role ARN.

    arn:aws:sts::111122223333:assumed-role/Approver/alice
        -> arn:aws:iam::111122223333:role/Approver
    Other ARNs are returned unchanged.
    """
    match = _ASSUMED_ROLE_RE.match(arn or "")
    if not match:
        return arn or ""
    partition, account, role_name, _session = match.groups()
    return f"arn:{partition}:iam::{account}:role/{role_name}"


def principal_from_api_event(event: Dict[str, Any]) -> Tuple[str, str]:
    """Return (principal_id, source) from an API Gateway proxy event.

    Supports REST API IAM authorization (requestContext.identity.userArn),
    HTTP API IAM authorization (requestContext.authorizer.iam.userArn), and
    JWT/Cognito authorizers (claims.sub). Returns ("", "") when the request is
    not authenticated; callers must treat that as a denial.
    """
    ctx = (event or {}).get("requestContext") or {}
    identity = ctx.get("identity") or {}
    user_arn = identity.get("userArn") or ""
    if user_arn:
        return user_arn, "iam"
    authorizer = ctx.get("authorizer") or {}
    iam_ctx = authorizer.get("iam") or {}
    if iam_ctx.get("userArn"):
        return iam_ctx["userArn"], "iam"
    claims = (authorizer.get("jwt") or {}).get("claims") or authorizer.get("claims") or {}
    if claims.get("sub"):
        issuer = claims.get("iss", "")
        return (f"{issuer}#{claims['sub']}" if issuer else claims["sub"]), "jwt"
    return "", ""


@dataclass
class AuthenticatedCaller:
    """The verified identity behind a request."""

    principal_id: str
    principal_type: str = "unknown"  # human | agent | unknown
    agent_id: str = ""
    roles: Set[str] = field(default_factory=set)
    source: str = ""  # iam | jwt | demo

    @property
    def is_agent(self) -> bool:
        return self.principal_type == "agent"

    @property
    def is_human(self) -> bool:
        return self.principal_type == "human"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "agent_id": self.agent_id,
            "roles": sorted(self.roles),
            "source": self.source,
        }


class RoleDirectory:
    """Principal -> governance roles, loaded from the GovernanceRolesTable.

    Items carry user_id (principal ARN, role ARN or JWT subject) and role. A
    role assigned to an IAM role ARN applies to every session of that role.
    """

    def __init__(self, assignments: Optional[Dict[str, Set[str]]] = None):
        self._assignments: Dict[str, Set[str]] = {
            k: set(v) for k, v in (assignments or {}).items()}

    @classmethod
    def from_table(cls, table) -> "RoleDirectory":
        assignments: Dict[str, Set[str]] = {}
        if table is None:
            return cls(assignments)
        try:
            resp = table.scan()
            items = list(resp.get("Items", []))
            while "LastEvaluatedKey" in resp:
                resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
                items.extend(resp.get("Items", []))
            for item in items:
                user = str(item.get("user_id", "") or "")
                role = str(item.get("role", "") or "")
                if user and role and str(item.get("status", "active")) == "active":
                    assignments.setdefault(user, set()).add(role)
        except Exception as exc:
            # Fail closed: nobody holds a role if the directory cannot load.
            logger.error(json.dumps({"event": "role_directory_load_failed", "error": str(exc)}))
            return cls({})
        return cls(assignments)

    @classmethod
    def for_principal(cls, table, principal_id: str) -> "RoleDirectory":
        """Roles for one principal, read with key queries instead of a table scan.

        The table's partition key is user_id, so the roles of a principal are
        one Query for the principal itself and one for its normalized role ARN
        (an assumed-role session inherits roles assigned to its role).
        """
        assignments: Dict[str, Set[str]] = {}
        if table is None or not principal_id:
            return cls(assignments)
        from boto3.dynamodb.conditions import Key
        try:
            for user in {principal_id, normalize_principal_arn(principal_id)} - {""}:
                # Strongly consistent: a removed or deactivated role assignment must stop applying at
                # the next request, as the runbook states (audit 2026-10-23, run-2).
                kwargs: Dict[str, Any] = {"KeyConditionExpression": Key("user_id").eq(user),
                                          "ConsistentRead": True}
                while True:
                    resp = table.query(**kwargs)
                    for item in resp.get("Items", []):
                        role = str(item.get("role", "") or "")
                        if role and str(item.get("status", "active")) == "active":
                            assignments.setdefault(user, set()).add(role)
                    if "LastEvaluatedKey" not in resp:
                        break
                    kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        except Exception as exc:
            # Fail closed: nobody holds a role if the directory cannot be read.
            logger.error(json.dumps({"event": "role_directory_query_failed", "error": str(exc)}))
            return cls({})
        return cls(assignments)

    def roles_for(self, principal_id: str) -> Set[str]:
        roles = set(self._assignments.get(principal_id, set()))
        normalized = normalize_principal_arn(principal_id)
        if normalized != principal_id:
            roles |= self._assignments.get(normalized, set())
        return roles


class AmbiguousAgentPrincipal(Exception):
    """More than one registered agent declares the same runtime principal."""


AgentPrincipals = Union[Mapping[str, str], Callable[[str], str]]


def _agent_id_for(principal_id: str, agent_principals: AgentPrincipals) -> str:
    if callable(agent_principals):
        return agent_principals(principal_id) or ""
    normalized = normalize_principal_arn(principal_id)
    return agent_principals.get(principal_id) or agent_principals.get(normalized) or ""


def is_bound_human_principal(principal_id: str, bound_human_roles: Iterable[str]) -> bool:
    """True for an IAM user, or a session of a role whose session name is bound to a person.

    A role's session name is chosen by whoever calls AssumeRole unless the role's trust policy binds
    it (sts:RoleSessionName = ${aws:username}, the stack's human roles, backlog HARD-09) or IAM
    Identity Center sets it. Separation of duties compares session names, so only those sessions may
    count as a person (audit 2026-10-23, run-2: unbound-assumed-role-session-name-as-human-identity).
    """
    if _IAM_USER_RE.match(principal_id or ""):
        return True
    role = normalize_principal_arn(principal_id)
    return role != (principal_id or "") and role in set(bound_human_roles)


def resolve_caller(principal_id: str, source: str, role_directory: RoleDirectory,
                   agent_principals: AgentPrincipals,
                   bound_human_roles: Optional[Iterable[str]] = None) -> AuthenticatedCaller:
    """Classify an authenticated principal as an agent or a human.

    agent_principals maps runtime principal ARNs (role ARNs) to agent ids, as
    declared in the agent registry, either as a mapping or as an indexed lookup
    function (AgentRegistry.agent_id_for_principal). Any principal whose role
    is a registered agent runtime principal is an agent, regardless of roles
    recorded for it. A principal claimed by more than one agent is classified
    as unknown, so every plane denies it.

    bound_human_roles, when given, is the set of IAM role ARNs whose sessions name a person. An IAM
    principal that is not an agent is then a human only if it is an IAM user or a session of one of
    those roles; any other IAM principal is unknown, so every plane denies it. None keeps the earlier
    rule (every non-agent principal is a human) for callers that do not configure it.
    """
    if not principal_id:
        return AuthenticatedCaller(principal_id="", principal_type="unknown", source=source)
    try:
        agent_id = _agent_id_for(principal_id, agent_principals)
    except AmbiguousAgentPrincipal as exc:
        logger.error(json.dumps({"event": "ambiguous_agent_principal", "principal_id": principal_id,
                                 "error": str(exc)}))
        return AuthenticatedCaller(principal_id=principal_id, principal_type="unknown", source=source)
    if agent_id:
        return AuthenticatedCaller(principal_id=principal_id, principal_type="agent",
                                   agent_id=agent_id, roles=set(), source=source)
    if (bound_human_roles is not None and source == "iam"
            and not is_bound_human_principal(principal_id, bound_human_roles)):
        logger.warning(json.dumps({"event": "unbound_human_principal", "principal_id": principal_id}))
        return AuthenticatedCaller(principal_id=principal_id, principal_type="unknown", source=source)
    return AuthenticatedCaller(principal_id=principal_id, principal_type="human",
                               roles=role_directory.roles_for(principal_id), source=source)


def check_body_identity(caller: AuthenticatedCaller, claimed: str) -> Tuple[bool, str]:
    """A body-supplied identity must match the authenticated principal."""
    if not claimed:
        return True, ""
    if claimed in (caller.principal_id, normalize_principal_arn(caller.principal_id)):
        return True, ""
    return False, ("approver_id in the request body does not match the authenticated "
                   "principal; identity is taken from the authenticated request only")


def _owners(registry_entry: Any) -> Iterable[str]:
    if registry_entry is None:
        return []
    names = [getattr(registry_entry, "owner", ""),
             getattr(registry_entry, "business_owner", ""),
             getattr(registry_entry, "technical_owner", "")]
    return [n for n in names if n]


_IAM_USER_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:user/(?:.*/)?([^/]+)$")
_IAM_ROLE_RE = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/(?:.*/)?[^/]+$")
_FEDERATED_RE = re.compile(r"^arn:aws[a-z-]*:sts::\d{12}:federated-user/([^/]+)$")
_JWT_PRINCIPAL_RE = re.compile(r"^https://[^#\s]+#\S+$")


def human_identity(principal: str) -> str:
    """The person behind a principal, for separation-of-duties comparisons.

    An STS assumed-role session ARN names its session. IAM Identity Center sets the session name of
    a permission-set session itself (check the value in a CloudTrail event before relying on it);
    for an IAM user assuming a role, the role's trust policy can require the session name to be the
    user name (sts:RoleSessionName = ${aws:username}). An IAM user ARN names the
    user. Anything else (a role ARN, a team name) is returned as given. Compared casefolded.
    """
    value = principal or ""
    match = _ASSUMED_ROLE_RE.match(value) or _IAM_USER_RE.match(value) or _FEDERATED_RE.match(value)
    if match:
        value = match.groups()[-1]
    return value.casefold()


def owner_is_resolvable(owner: str) -> bool:
    """True when an owner value names principals separation of duties can compare.

    IAM user, role, assumed-role session and federated-user ARNs, and gateway JWT principals
    (<issuer>#<subject>). A team name, an email address or free text names no principal: whether an
    approver belongs to it cannot be checked (audit 2026-10-23, run-2: sod-owner-identity-compared-verbatim).
    """
    value = owner or ""
    return bool(_ASSUMED_ROLE_RE.match(value) or _IAM_USER_RE.match(value) or _IAM_ROLE_RE.match(value)
                or _FEDERATED_RE.match(value) or _JWT_PRINCIPAL_RE.match(value))


def check_approver_eligibility(caller: AuthenticatedCaller, approval_item: Dict[str, Any],
                               registry_entry: Any) -> Tuple[bool, str]:
    """Separation of duties for approving an escalated request.

    Rules (all must hold):
      * the caller is authenticated and is a human principal (no agent of any
        type, worker or guardian, can approve anything, including itself)
      * the caller holds an approver role
      * the caller is not the agent itself and not one of its owners
      * every recorded owner is a principal the check can compare (fails closed otherwise)

    registry_entry None skips the owner checks: refusing (deny, withdraw) only narrows authority.
    """
    if not caller.principal_id:
        return False, "approval requires an authenticated principal"
    if caller.is_agent:
        return False, (f"principal is registered as agent '{caller.agent_id}'; agents "
                       "(workers and guardians alike) cannot approve requests")
    if not caller.is_human:
        return False, "approver identity could not be verified as a human principal"
    if not (caller.roles & APPROVER_ROLES):
        return False, (f"principal holds none of the approver roles "
                       f"{sorted(APPROVER_ROLES)}")
    agent_id = str(approval_item.get("agent_id", ""))
    candidates = {caller.principal_id, normalize_principal_arn(caller.principal_id)}
    if agent_id and agent_id in candidates:
        return False, "an agent cannot approve its own request"
    person = human_identity(caller.principal_id)
    for owner in _owners(registry_entry):
        if owner in candidates:
            return False, "separation of duties: the agent's owner cannot approve its requests"
        if not owner_is_resolvable(owner):
            return False, (f"separation of duties cannot be checked: the agent's owner {owner!r} is not an IAM "
                           "user, role or session ARN or a gateway principal; record owners as principals")
        # The same person under another role: an owner who also holds an approver role must not
        # approve their own agent's requests (audit 2026-10-21, approval/sod-compares-iam-principal-
        # strings-not-human-identity).
        if _IAM_ROLE_RE.match(owner) or _JWT_PRINCIPAL_RE.match(owner):
            continue  # a role owns every session of it, covered by the candidates check above
        if person and human_identity(owner) == person:
            return False, ("separation of duties: the approver is the same person as the agent's owner "
                           "(same session or user name under another role)")
    return True, ""


def check_admin(caller: AuthenticatedCaller, required_roles=ADMIN_ROLES) -> Tuple[bool, str]:
    """Admin-plane gate: an authenticated human holding a required role."""
    if not caller.principal_id:
        return False, "administrative action requires an authenticated principal"
    if caller.is_agent:
        return False, (f"principal is registered as agent '{caller.agent_id}'; "
                       "administrative actions are human-only")
    if not caller.is_human:
        return False, "administrative action requires a verified human principal"
    if not (caller.roles & set(required_roles)):
        return False, f"principal holds none of the roles {sorted(required_roles)}"
    return True, ""
