"""AWS adapter: delegated authority enforced by STS session policies.

For each verified grant the adapter calls sts:AssumeRole on a dedicated
execution role with an INLINE SESSION POLICY derived from the grant. The
effective permissions of the temporary credentials are the intersection of
the role's policy and the session policy, so they can never exceed the grant:

  * Action:   only the operation's IAM actions (for AWS.ReadObject: s3:GetObject)
  * Resource: only the exact target ARN from the grant
  * Condition: aws:CurrentTime before the grant's expires_at. STS issues
    credentials for at least 900 seconds; the condition makes them useless
    once the (shorter) grant expires.

Session tags and SourceIdentity carry grant_id, agent_id and decision_id into
CloudTrail, so every API call made with the credential traces back to the
decision that authorized it.

Each grant gets its own credential and its own session policy. Nothing is
shared or mutated between agents: agent A -> credential A -> envelope A.
(The repository's permission-boundary swap on a shared role remains a
separate research experiment; it is not used on this path.)

The credential is held only inside the CredentialHandle; it is never logged,
returned or written to evidence.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from .base import (
    MODE_LIVE,
    MODE_MOCK,
    BrokerRefusal,
    CredentialHandle,
    CredentialProvider,
    ExecutionResult,
    new_credential_reference,
    utc_now,
)

STS_MIN_DURATION_SECONDS = 900


def resource_arn_for(target_resource: str, region: str = "", account: str = "",
                     partition: str = "aws") -> str:
    """Map a grant target ('aws/s3/<bucket>/<key>' or 'aws/states/<name>') to an ARN."""
    parts = target_resource.split("/")
    if len(parts) >= 4 and parts[0] == "aws" and parts[1] == "s3":
        bucket, key = parts[2], "/".join(parts[3:])
        if not bucket or not key or "*" in target_resource:
            raise BrokerRefusal("an S3 grant must name one exact object")
        return f"arn:{partition}:s3:::{bucket}/{key}"
    if len(parts) == 3 and parts[0] == "aws" and parts[1] == "states":
        if not (region and account):
            raise BrokerRefusal("region and account are required for a Step Functions grant")
        return f"arn:{partition}:states:{region}:{account}:stateMachine:{parts[2]}"
    raise BrokerRefusal(f"target {target_resource!r} is not an AWS resource this adapter can scope")


def _iam_time(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_session_policy(grant, spec, resource_arn: str) -> Dict[str, Any]:
    """The inline session policy for one grant: one action set, one ARN, one deadline."""
    if not spec.aws_actions:
        raise BrokerRefusal(f"{spec.operation_id} declares no AWS actions")
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DelegatedAuthorityGrant",
            "Effect": "Allow",
            "Action": sorted(spec.aws_actions),
            "Resource": [resource_arn],
            "Condition": {"DateLessThan": {"aws:CurrentTime": _iam_time(grant.expires_at)}},
        }],
    }


def _tag(value: str) -> str:
    """Session tag values allow [\\w+=,.@:/-] and at most 256 characters."""
    return "".join(c if c.isalnum() or c in "_+=,.@:/-" else "-" for c in value)[:256]


def _source_identity(value: str) -> str:
    """SourceIdentity allows [\\w+=,.@-] and 2 to 64 characters."""
    cleaned = "".join(c if c.isalnum() or c in "_+=,.@-" else "-" for c in value)[:64]
    return cleaned if len(cleaned) >= 2 else "agent-" + cleaned


class AwsStsAdapter(CredentialProvider):
    name = "aws"

    def __init__(self, mode: str = MODE_MOCK, sts_client=None, role_arn: str = "",
                 region: str = "", account: str = "", client_factory=None,
                 mock_objects: Optional[Dict[str, bytes]] = None):
        if mode not in (MODE_MOCK, MODE_LIVE):
            raise ValueError(f"unknown provider mode {mode!r}")
        if mode == MODE_LIVE and (sts_client is None or not role_arn):
            raise BrokerRefusal("live AWS mode needs an STS client and DELEGATED_EXECUTION_ROLE_ARN")
        self.mode = mode
        self._sts = sts_client
        self._role_arn = role_arn
        self._region = region
        self._account = account
        self._client_factory = client_factory
        self._mock_objects = dict(mock_objects or {})
        self.last_session_policy: Dict[str, Any] = {}

    def exchange(self, verified, spec) -> CredentialHandle:
        grant = verified.grant
        resource_arn = resource_arn_for(grant.target_resource, self._region, self._account)
        policy = build_session_policy(grant, spec, resource_arn)
        self.last_session_policy = policy
        issued = utc_now()
        details = {"session_policy_actions": policy["Statement"][0]["Action"],
                   "session_policy_resource": resource_arn,
                   "session_policy_deadline": policy["Statement"][0]["Condition"]["DateLessThan"]["aws:CurrentTime"],
                   "role_session_name": grant.grant_id[:64]}
        if self.mode == MODE_MOCK:
            return CredentialHandle(
                provider=self.name, credential_type="aws_sts_session (simulated)",
                credential_reference=new_credential_reference(), issued_at=issued.isoformat(),
                expires_at=grant.expires_at, effective_until=grant.expires_at,
                scopes=list(spec.provider_scopes), grant_id=grant.grant_id, mode=self.mode,
                details=details, _secret={"simulated": True})
        resp = self._sts.assume_role(
            RoleArn=self._role_arn,
            RoleSessionName=grant.grant_id[:64],
            Policy=json.dumps(policy, separators=(",", ":")),
            DurationSeconds=STS_MIN_DURATION_SECONDS,
            SourceIdentity=_source_identity(grant.agent_id),
            Tags=[{"Key": "grant_id", "Value": _tag(grant.grant_id)},
                  {"Key": "agent_id", "Value": _tag(grant.agent_id)},
                  {"Key": "decision_id", "Value": _tag(grant.decision_id)}],
        )
        creds = resp["Credentials"]
        expiration = creds["Expiration"]
        expiration_iso = expiration.isoformat() if hasattr(expiration, "isoformat") else str(expiration)
        details["assumed_role_arn"] = resp.get("AssumedRoleUser", {}).get("Arn", "")
        return CredentialHandle(
            provider=self.name, credential_type="aws_sts_session",
            credential_reference=new_credential_reference(), issued_at=issued.isoformat(),
            expires_at=expiration_iso, effective_until=grant.expires_at,
            scopes=list(spec.provider_scopes), grant_id=grant.grant_id, mode=self.mode,
            details=details,
            _secret={"aws_access_key_id": creds["AccessKeyId"],
                     "aws_secret_access_key": creds["SecretAccessKey"],
                     "aws_session_token": creds["SessionToken"]},
        )

    def _client(self, service: str, handle: CredentialHandle):
        if self._client_factory is not None:
            return self._client_factory(service, handle._secret)
        import boto3
        return boto3.client(service, region_name=self._region or None, **handle._secret)

    @staticmethod
    def _split_s3(target_resource: str) -> Tuple[str, str]:
        parts = target_resource.split("/")
        return parts[2], "/".join(parts[3:])

    def execute(self, handle: CredentialHandle, verified, spec) -> ExecutionResult:
        target = verified.grant.target_resource
        if spec.operation_id == "AWS.ReadObject":
            bucket, key = self._split_s3(target)
            if self.mode == MODE_MOCK:
                body = self._mock_objects.get(f"{bucket}/{key}")
                if body is None:
                    return ExecutionResult(self.name, spec.operation_id, "failed", {}, "object not found")
            else:
                body = self._client("s3", handle).get_object(Bucket=bucket, Key=key)["Body"].read()
            # Never return object content; prove the read with size and hash.
            summary = {"bucket": bucket, "key": key, "bytes": len(body),
                       "sha256": hashlib.sha256(body).hexdigest()}
            probe_key = os.environ.get("DEMO_ENFORCEMENT_PROBE_KEY", "")
            if self.mode == MODE_LIVE and probe_key:
                # Live demo only: show that the SAME credential cannot read
                # anything else, because the session policy names one object.
                summary["iam_probe"] = self.probe_out_of_scope(handle, bucket, probe_key)
            return ExecutionResult(self.name, spec.operation_id, "success", summary)
        if spec.operation_id == "AWS.StartWorkflow":
            arn = resource_arn_for(target, self._region, self._account)
            params = verified.canonical_request["tool_parameters"]
            if self.mode == MODE_MOCK:
                return ExecutionResult(self.name, spec.operation_id, "success",
                                       {"state_machine": arn, "execution": "simulated",
                                        "input_reference": params["input_reference"]})
            resp = self._client("stepfunctions", handle).start_execution(
                stateMachineArn=arn, name=verified.grant.grant_id[:80],
                input=json.dumps({"input_reference": params["input_reference"]}))
            return ExecutionResult(self.name, spec.operation_id, "success",
                                   {"state_machine": arn, "execution_arn": resp["executionArn"]})
        raise BrokerRefusal(f"AWS adapter does not implement {spec.operation_id}")

    def probe_out_of_scope(self, handle: CredentialHandle, bucket: str, key: str) -> Dict[str, Any]:
        """Live demo: try to read a DIFFERENT object with the same credential.

        With real STS the session policy makes this fail with AccessDenied,
        which shows the credential is bounded by the grant, not by the role.
        """
        if self.mode != MODE_LIVE:
            return {"probe": "skipped", "reason": "session policies are only enforced by real AWS STS"}
        try:
            self._client("s3", handle).get_object(Bucket=bucket, Key=key)
            return {"probe": "UNEXPECTED_ALLOW", "object": f"{bucket}/{key}"}
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", type(exc).__name__)
            return {"probe": "denied", "object": f"{bucket}/{key}", "error_code": code}
