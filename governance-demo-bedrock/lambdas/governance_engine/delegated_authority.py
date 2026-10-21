"""Delegated Authority Grants ("hall passes").

A DelegatedAuthorityGrant is signed, short-lived, narrowly scoped, revocable
proof that the governance control plane authorized ONE specific action for
ONE agent. It is not a credential and never contains one. A credential broker
exchanges a verified grant for a provider-native, target-specific temporary
credential (for AWS: STS AssumeRole with an inline session policy).

Properties:
  * Signed with an asymmetric KMS key (ECDSA_SHA_256 over a SHA-256 digest of
    the canonical immutable fields). Verification fails closed on any
    mismatch, including a grant signed by a different key.
  * Persisted in DynamoDB. State changes (consume, revoke, expire) are
    conditional writes, so a one-use grant cannot be used twice, even by
    concurrent callers.
  * Bound to the exact request: agent, session, provider, operation, target,
    parameters, data class and amount, through the request digest.
  * Short-lived: expires_at is absolute; DynamoDB TTL only cleans up, it is
    never relied on for enforcement.

States: ACTIVE -> CONSUMED | REVOKED | EXPIRED.
"""

import base64
import fnmatch
import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Tuple

from request_canonicalization import (
    CanonicalizationError,
    canonical_json,
    canonicalize_action_request,
    compute_action_request_digest,
    to_dynamodb_safe,
    to_json_safe,
)

logger = logging.getLogger(__name__)

ACTIVE = "ACTIVE"
CONSUMED = "CONSUMED"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"
VALID_STATUSES = (ACTIVE, CONSUMED, REVOKED, EXPIRED)

SIGNING_ALGORITHM = "ECDSA_SHA_256"
TTL_GRACE_SECONDS = 24 * 3600  # keep finished grants queryable for a day

# Fields covered by the signature. Mutable state (status, uses_remaining and
# the consumption/revocation timestamps) lives only in the store.
SIGNED_FIELDS = (
    "grant_id", "agent_id", "session_id", "delegated_by", "provider", "operation_id",
    "target_resource", "resource_patterns", "parameter_constraints", "data_classes",
    "spend_limit", "scope_level", "environment", "decision_id", "approval_id",
    "policy_version_hash", "request_digest", "issued_at", "expires_at",
    "expires_at_epoch", "max_uses", "signing_key_id", "signature_algorithm",
)


class GrantSigningError(RuntimeError):
    """A grant could not be signed; the grant is not minted (fail closed)."""


# ---------------------------------------------------------------------------
# Signers
# ---------------------------------------------------------------------------

class KmsGrantSigner:
    """Signs grant digests with an asymmetric AWS KMS key (ECC_NIST_P256)."""

    algorithm = SIGNING_ALGORITHM
    demo_only = False

    def __init__(self, kms_client, key_id: str):
        if kms_client is None or not key_id:
            raise GrantSigningError("a KMS client and signing key id are required")
        self._kms = kms_client
        self.key_id = key_id

    def sign(self, hex_digest: str) -> str:
        try:
            resp = self._kms.sign(KeyId=self.key_id, Message=bytes.fromhex(hex_digest),
                                  MessageType="DIGEST", SigningAlgorithm=self.algorithm)
        except Exception as exc:
            raise GrantSigningError(f"KMS signing failed: {type(exc).__name__}") from exc
        return base64.b64encode(resp["Signature"]).decode("ascii")

    def verify(self, hex_digest: str, signature_b64: str) -> bool:
        try:
            resp = self._kms.verify(KeyId=self.key_id, Message=bytes.fromhex(hex_digest),
                                    MessageType="DIGEST", Signature=base64.b64decode(signature_b64),
                                    SigningAlgorithm=self.algorithm)
            return bool(resp.get("SignatureValid", False))
        except Exception:
            return False


class LocalDemoSigner:
    """In-process ECDSA P-256 signer for offline demos and tests ONLY.

    Generates an ephemeral key at construction; nothing is persisted and no
    key material exists in the repository. Production uses KmsGrantSigner.
    """

    algorithm = SIGNING_ALGORITHM
    demo_only = True

    def __init__(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        self._key = ec.generate_private_key(ec.SECP256R1())
        public = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.key_id = "local-demo-ephemeral:" + hashlib.sha256(public).hexdigest()[:16]

    def sign(self, hex_digest: str) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        sig = self._key.sign(bytes.fromhex(hex_digest), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return base64.b64encode(sig).decode("ascii")

    def verify(self, hex_digest: str, signature_b64: str) -> bool:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        try:
            self._key.public_key().verify(base64.b64decode(signature_b64), bytes.fromhex(hex_digest),
                                          ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            return True
        except (InvalidSignature, ValueError):
            return False


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

@dataclass
class DelegatedAuthorityGrant:
    grant_id: str
    agent_id: str
    session_id: str
    delegated_by: str
    provider: str
    operation_id: str
    target_resource: str
    resource_patterns: List[str]
    parameter_constraints: Dict[str, Any]
    data_classes: List[str]
    spend_limit: Dict[str, Any]
    scope_level: int
    environment: str
    decision_id: str
    approval_id: str
    policy_version_hash: str
    request_digest: str
    issued_at: str
    expires_at: str
    expires_at_epoch: int
    max_uses: int
    uses_remaining: int
    status: str = ACTIVE
    signing_key_id: str = ""
    signature_algorithm: str = SIGNING_ALGORITHM
    signature: str = ""
    consumed_at: str = ""
    revoked_at: str = ""
    revoked_by: str = ""
    revoke_reason: str = ""

    def signing_digest(self) -> str:
        body = {name: getattr(self, name) for name in SIGNED_FIELDS}
        return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()

    def to_item(self) -> Dict[str, Any]:
        item = to_dynamodb_safe(asdict(self))
        item["ttl_expiry"] = int(self.expires_at_epoch) + TTL_GRACE_SECONDS
        return item

    @classmethod
    def from_item(cls, item: Dict[str, Any]) -> "DelegatedAuthorityGrant":
        data = {k: item.get(k) for k in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        for key in ("scope_level", "expires_at_epoch", "max_uses", "uses_remaining"):
            data[key] = int(data.get(key) or 0)
        for key in ("resource_patterns", "data_classes"):
            data[key] = list(data.get(key) or [])
        for key in ("parameter_constraints", "spend_limit"):
            data[key] = dict(data.get(key) or {})
        for key, val in list(data.items()):
            if val is None:
                data[key] = ""
        return cls(**data)

    def public_view(self) -> Dict[str, Any]:
        """Safe, display-ready summary (there is no secret in a grant)."""
        return to_json_safe({
            "grant_id": self.grant_id, "agent_id": self.agent_id, "session_id": self.session_id,
            "delegated_by": self.delegated_by, "provider": self.provider,
            "operation_id": self.operation_id, "target_resource": self.target_resource,
            "resource_patterns": self.resource_patterns, "spend_limit": self.spend_limit,
            "data_classes": self.data_classes, "scope_level": self.scope_level,
            "environment": self.environment, "decision_id": self.decision_id,
            "approval_id": self.approval_id or None, "issued_at": self.issued_at,
            "expires_at": self.expires_at, "max_uses": self.max_uses,
            "uses_remaining": self.uses_remaining, "status": self.status,
            "signing_key_id": self.signing_key_id, "signature_algorithm": self.signature_algorithm,
            "signature_preview": (self.signature[:16] + "...") if self.signature else "",
            "policy_version_hash": self.policy_version_hash[:16] + "...",
            "request_digest": self.request_digest,
        })


@dataclass
class GrantCheck:
    name: str
    result: str  # pass | fail
    detail: str = ""


@dataclass
class GrantVerification:
    ok: bool
    reason: str
    grant: Optional[DelegatedAuthorityGrant] = None
    checks: List[GrantCheck] = field(default_factory=list)

    def checks_view(self) -> List[Dict[str, str]]:
        return [{"check": c.name, "result": c.result, "detail": c.detail} for c in self.checks]


class VerifiedGrant:
    """Proof that a grant was verified AND atomically consumed for one use.

    Only GrantStore.verify_and_consume creates these. The credential broker
    refuses anything else, so no code path can obtain a credential from an
    unverified or unconsumed grant.
    """

    __slots__ = ("grant", "canonical_request", "_issuer", "consumed")

    def __init__(self, grant: DelegatedAuthorityGrant, canonical_request: Dict[str, Any], issuer: Any):
        self.grant = grant
        self.canonical_request = canonical_request
        self._issuer = issuer
        self.consumed = True

    def issued_by(self, store: Any) -> bool:
        return self._issuer is store


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cond_failed(exc: Exception) -> bool:
    return "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc)


class GrantStore:
    """DynamoDB-backed grant lifecycle: mint, get, verify, consume, revoke."""

    def __init__(self, table, signer, clock: Callable[[], datetime] = _now):
        self._table = table
        self._signer = signer
        self._clock = clock

    @property
    def signer(self):
        return self._signer

    # ------------------------------------------------------------- mint
    def build(self, *, agent_id: str, session_id: str, delegated_by: str, provider: str,
              operation_id: str, target_resource: str, resource_patterns: List[str],
              parameter_constraints: Dict[str, Any], data_classes: List[str],
              spend_limit: Dict[str, Any], scope_level: int, environment: str, decision_id: str,
              approval_id: str, policy_version_hash: str, request_digest: str,
              ttl_seconds: int, max_uses: int = 1) -> DelegatedAuthorityGrant:
        """Create and sign a grant without writing it."""
        if ttl_seconds <= 0 or max_uses <= 0:
            raise ValueError("ttl_seconds and max_uses must be positive")
        issued = self._clock().replace(microsecond=0)
        expires = issued + timedelta(seconds=int(ttl_seconds))
        grant = DelegatedAuthorityGrant(
            grant_id="dag-" + uuid.uuid4().hex, agent_id=agent_id, session_id=session_id,
            delegated_by=delegated_by, provider=provider, operation_id=operation_id,
            target_resource=target_resource, resource_patterns=list(resource_patterns),
            parameter_constraints=dict(parameter_constraints or {}), data_classes=list(data_classes),
            spend_limit=dict(spend_limit or {}), scope_level=int(scope_level), environment=environment,
            decision_id=decision_id, approval_id=approval_id or "",
            policy_version_hash=policy_version_hash, request_digest=request_digest,
            issued_at=issued.isoformat(), expires_at=expires.isoformat(),
            expires_at_epoch=int(expires.timestamp()), max_uses=int(max_uses),
            uses_remaining=int(max_uses), status=ACTIVE,
            signing_key_id=self._signer.key_id, signature_algorithm=self._signer.algorithm,
        )
        grant.signature = self._signer.sign(grant.signing_digest())
        return grant

    def mint(self, **fields) -> DelegatedAuthorityGrant:
        """Create, sign and write a grant. Takes the same keyword arguments as build."""
        grant = self.build(**fields)
        self._table.put_item(Item=grant.to_item(), ConditionExpression="attribute_not_exists(grant_id)")
        self._log_minted(grant)
        return grant

    def put_transact_item(self, grant: DelegatedAuthorityGrant) -> Dict[str, Any]:
        """Put for a DynamoDB transaction that writes the grant once.

        Values are plain Python types: the client of a boto3 DynamoDB resource
        table converts them to DynamoDB attribute values itself.
        """
        return {"Put": {
            "TableName": self._table.name,
            "Item": grant.to_item(),
            "ConditionExpression": "attribute_not_exists(grant_id)",
        }}

    def mint_in_transaction(self, grant: DelegatedAuthorityGrant,
                            other_items: List[Dict[str, Any]]) -> DelegatedAuthorityGrant:
        """Write the grant together with other_items: all of them or none.

        Raises botocore ClientError with code TransactionCanceledException when
        any condition fails; nothing is written in that case.
        """
        self._table.meta.client.transact_write_items(
            TransactItems=[*other_items, self.put_transact_item(grant)])
        self._log_minted(grant)
        return grant

    @staticmethod
    def _log_minted(grant: DelegatedAuthorityGrant) -> None:
        logger.info(json.dumps({"audit_event": "authority_grant_minted", "grant_id": grant.grant_id,
                                "agent_id": grant.agent_id, "operation_id": grant.operation_id,
                                "decision_id": grant.decision_id, "approval_id": grant.approval_id or None,
                                "expires_at": grant.expires_at}))

    # -------------------------------------------------------------- get
    def get(self, grant_id: str) -> Optional[DelegatedAuthorityGrant]:
        item = self._table.get_item(Key={"grant_id": grant_id}, ConsistentRead=True).get("Item")
        return DelegatedAuthorityGrant.from_item(item) if item else None

    def list_for_agent(self, agent_id: str) -> List[DelegatedAuthorityGrant]:
        from boto3.dynamodb.conditions import Key
        resp = self._table.query(IndexName="ByAgentId", KeyConditionExpression=Key("agent_id").eq(agent_id))
        items = list(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = self._table.query(IndexName="ByAgentId", KeyConditionExpression=Key("agent_id").eq(agent_id),
                                     ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
        return [DelegatedAuthorityGrant.from_item(i) for i in items]

    # ----------------------------------------------------------- verify
    def verify(self, grant_id: str, request: Dict[str, Any]) -> GrantVerification:
        """Verify a presented request against a stored grant. Read-only."""
        checks: List[GrantCheck] = []

        def fail(name: str, detail: str, grant=None) -> GrantVerification:
            checks.append(GrantCheck(name, "fail", detail))
            return GrantVerification(False, detail, grant, checks)

        try:
            grant = self.get(grant_id)
        except Exception as exc:
            return fail("grant_exists", f"grant lookup failed ({type(exc).__name__}); failing closed")
        if grant is None:
            return fail("grant_exists", f"grant {grant_id} does not exist")
        checks.append(GrantCheck("grant_exists", "pass", grant_id))

        if grant.signing_key_id != self._signer.key_id or not grant.signature:
            return fail("signature", "grant was not signed by the configured authority key", grant)
        if not self._signer.verify(grant.signing_digest(), grant.signature):
            return fail("signature", "grant signature is invalid (tampered or forged)", grant)
        checks.append(GrantCheck("signature", "pass", f"{grant.signature_algorithm} via {grant.signing_key_id}"))

        if grant.status != ACTIVE:
            return fail("status", f"grant status is {grant.status}", grant)
        now_epoch = int(self._clock().timestamp())
        if now_epoch >= grant.expires_at_epoch:
            self._mark_expired(grant)
            return fail("expiry", f"grant expired at {grant.expires_at}", grant)
        if grant.uses_remaining <= 0:
            return fail("uses_remaining", "grant has no uses remaining", grant)
        checks.append(GrantCheck("status", "pass",
                                 f"ACTIVE, {grant.uses_remaining} use(s) left, expires {grant.expires_at}"))

        try:
            canonical = canonicalize_action_request(request)
        except CanonicalizationError as exc:
            return fail("request", f"request could not be canonicalized ({exc})", grant)

        for name, expected, actual in (
            ("agent", grant.agent_id, canonical["agent_id"]),
            ("session", grant.session_id, canonical["session_id"]),
            ("provider", grant.provider, canonical["provider"]),
            ("operation", grant.operation_id, canonical["operation_id"]),
            ("environment", grant.environment, canonical["environment"]),
        ):
            if expected != actual:
                return fail(f"{name}_match", f"{name} mismatch: grant is for '{expected}', request has '{actual}'", grant)
        checks.append(GrantCheck("binding", "pass", "agent, session, provider, operation, environment match"))

        target = canonical["target_resource"]
        if target != grant.target_resource or not any(
                fnmatch.fnmatchcase(target, p) for p in grant.resource_patterns):
            return fail("resource", f"target '{target}' is outside the granted resource boundary", grant)
        checks.append(GrantCheck("resource", "pass", target))

        if canonical["data_class"] and canonical["data_class"] not in grant.data_classes:
            return fail("data_class", f"data class {canonical['data_class']} is not granted", grant)

        violation = _parameter_constraint_violation(grant.parameter_constraints, canonical["tool_parameters"])
        if violation:
            return fail("parameter_constraints", violation, grant)

        if grant.spend_limit:
            fin = canonical["financial_context"]
            limit = Decimal(str(grant.spend_limit.get("amount", "0")))
            if fin.get("currency") != grant.spend_limit.get("currency") or \
                    Decimal(str(fin.get("transaction_amount", "0"))) > limit:
                return fail("spend_limit", (f"transaction {fin.get('currency')} {fin.get('transaction_amount')} "
                                            f"exceeds the granted {grant.spend_limit.get('currency')} {limit}"), grant)
            checks.append(GrantCheck("spend_limit", "pass",
                                     f"{fin.get('currency')} {fin.get('transaction_amount')} <= {limit}"))

        presented = compute_action_request_digest(canonical, grant.policy_version_hash)
        if not hmac.compare_digest(presented, grant.request_digest):
            return fail("request_digest", "request does not match the exact request this grant authorizes", grant)
        checks.append(GrantCheck("request_digest", "pass", "exact request binding verified"))
        return GrantVerification(True, "grant verified", grant, checks)

    def verify_and_consume(self, grant_id: str, request: Dict[str, Any]) -> Tuple[GrantVerification, Optional[VerifiedGrant]]:
        """Verify, then atomically consume one use. Both must succeed."""
        verification = self.verify(grant_id, request)
        if not verification.ok:
            return verification, None
        ok, reason, grant = self.consume(grant_id)
        if not ok:
            verification.checks.append(GrantCheck("consume", "fail", reason))
            return GrantVerification(False, reason, verification.grant, verification.checks), None
        verification.checks.append(GrantCheck("consume", "pass",
                                              f"status {grant.status}, {grant.uses_remaining} use(s) left"))
        verification.grant = grant
        return verification, VerifiedGrant(grant, canonicalize_action_request(request), self)

    # ---------------------------------------------------------- consume
    def consume(self, grant_id: str, attempts: int = 3) -> Tuple[bool, str, Optional[DelegatedAuthorityGrant]]:
        """Atomically use one use of an ACTIVE, unexpired grant."""
        for _ in range(attempts):
            grant = self.get(grant_id)
            if grant is None:
                return False, "grant does not exist", None
            if grant.status != ACTIVE or grant.uses_remaining <= 0:
                return False, f"grant already {grant.status.lower()} (replay attempt)", grant
            now = self._clock()
            remaining = grant.uses_remaining - 1
            new_status = CONSUMED if remaining == 0 else ACTIVE
            try:
                self._table.update_item(
                    Key={"grant_id": grant_id},
                    UpdateExpression="SET #u = :remaining, #s = :status, #c = :now",
                    ConditionExpression="#s = :active AND #u = :expected AND #e > :epoch",
                    ExpressionAttributeNames={"#u": "uses_remaining", "#s": "status",
                                              "#c": "consumed_at", "#e": "expires_at_epoch"},
                    ExpressionAttributeValues={":remaining": remaining, ":status": new_status,
                                               ":now": now.isoformat(), ":active": ACTIVE,
                                               ":expected": grant.uses_remaining,
                                               ":epoch": int(now.timestamp())},
                )
            except Exception as exc:
                if _cond_failed(exc):
                    continue  # lost a race; re-read and decide again
                return False, f"grant store unavailable ({type(exc).__name__}); failing closed", grant
            grant.uses_remaining, grant.status, grant.consumed_at = remaining, new_status, now.isoformat()
            logger.info(json.dumps({"audit_event": "authority_grant_consumed", "grant_id": grant_id,
                                    "uses_remaining": remaining, "status": new_status}))
            return True, "consumed", grant
        grant = self.get(grant_id)
        return False, f"grant already {(grant.status if grant else 'missing').lower()} (replay attempt)", grant

    # ----------------------------------------------------------- revoke
    def revoke(self, grant_id: str, revoked_by: str, reason: str) -> Tuple[bool, str]:
        now = self._clock().isoformat()
        try:
            self._table.update_item(
                Key={"grant_id": grant_id},
                UpdateExpression="SET #s = :revoked, #ra = :now, #rb = :by, #rr = :reason",
                ConditionExpression="#s = :active",
                ExpressionAttributeNames={"#s": "status", "#ra": "revoked_at", "#rb": "revoked_by",
                                          "#rr": "revoke_reason"},
                ExpressionAttributeValues={":revoked": REVOKED, ":active": ACTIVE, ":now": now,
                                           ":by": revoked_by, ":reason": reason},
            )
        except Exception as exc:
            if _cond_failed(exc):
                grant = self.get(grant_id)
                return False, f"grant is {grant.status if grant else 'missing'}; only ACTIVE grants can be revoked"
            return False, f"grant store unavailable ({type(exc).__name__})"
        logger.info(json.dumps({"audit_event": "authority_grant_revoked", "grant_id": grant_id,
                                "revoked_by": revoked_by, "reason": reason}))
        return True, "revoked"

    def revoke_all_for_agent(self, agent_id: str, revoked_by: str, reason: str) -> List[str]:
        revoked = []
        for grant in self.list_for_agent(agent_id):
            if grant.status == ACTIVE and self.revoke(grant.grant_id, revoked_by, reason)[0]:
                revoked.append(grant.grant_id)
        return revoked

    def _mark_expired(self, grant: DelegatedAuthorityGrant) -> None:
        try:
            self._table.update_item(
                Key={"grant_id": grant.grant_id}, UpdateExpression="SET #s = :expired",
                ConditionExpression="#s = :active", ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":expired": EXPIRED, ":active": ACTIVE})
        except Exception:
            pass  # best effort; verification already failed closed


def _parameter_constraint_violation(constraints: Dict[str, Any], params: Dict[str, Any]) -> str:
    """Grant-level parameter limits ({name: {max, min, enum, equals}})."""
    for name, rule in (constraints or {}).items():
        if name not in params:
            return f"parameter {name} is required by the grant"
        value = params[name]
        if "equals" in rule and canonical_json(value) != canonical_json(rule["equals"]):
            return f"parameter {name} differs from the granted value"
        if "enum" in rule and value not in rule["enum"]:
            return f"parameter {name} is outside the granted values"
        if "max" in rule and Decimal(str(value)) > Decimal(str(rule["max"])):
            return f"parameter {name}={value} exceeds the granted maximum {rule['max']}"
        if "min" in rule and Decimal(str(value)) < Decimal(str(rule["min"])):
            return f"parameter {name}={value} is below the granted minimum {rule['min']}"
    return ""
