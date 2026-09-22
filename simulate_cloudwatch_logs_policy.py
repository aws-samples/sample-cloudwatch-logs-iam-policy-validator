# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/usr/bin/env python3
"""Simulate a custom IAM policy against every CloudWatch Logs IAM action.

This standalone script evaluates a user-provided customer-managed IAM policy
against the full set of ``logs:`` IAM actions, for two CloudWatch Logs resource
ARN forms, using ``aws iam simulate-custom-policy``. It prints one row per
action with the allow/deny decision for each resource form.

Only the Python standard library is used. AWS access is performed by shelling
out to the already-installed and already-authenticated AWS CLI; no AWS SDK
(boto3) is imported and no credentials are read or printed by this script.

Policy input
------------
Each simulation batch is sent as a complete, API-shaped request written to a
temporary JSON file and passed with the global
``--cli-input-json file://<request-file>`` option. That request file carries
``PolicyInputList`` (an array holding the validated policy document as a JSON
*string*), ``ActionNames``, and ``ResourceArns``.

The full request is routed through ``--cli-input-json`` because
``--policy-input-list`` is a *list-valued* parameter: the AWS CLI does not
expand a ``file://`` URI into that list's elements, so
``--policy-input-list file://<policy>`` is received by IAM as one literal
policy string and rejected as a malformed document (observed as AWS CLI exit
254 on the first resource). Supplying the whole request via ``--cli-input-json``
avoids the list-vs-file ambiguity entirely.

The policy body is validated as JSON locally, then written only into the
short-lived request file (created with ``0600`` permissions via ``tempfile``
and removed in a ``finally`` block). It never appears in argv /
``/proc/<pid>/cmdline`` and is never logged or printed.

Resource ARNs
-------------
IAM simulation requires fully-formed, concrete ARNs. The two documented
CloudWatch Logs resource ARN forms this script builds are::

    arn:{partition}:logs:{region}:{account}:log-group:{LogGroupName}:log-stream:*
    arn:{partition}:logs:{region}:{account}:log-group:{LogGroupName}

The user's shorthand ``log-group:MyGroup:log-stream:*`` omits the
``logs:{region}:{account}`` prefix and is therefore NOT a valid AWS ARN; this
script always fills in those fields and builds the fully-qualified
``arn:{partition}:logs:...`` forms shown above. The trailing ``log-stream:*``
in the first form is an intentional wildcard over *log-stream names* within
the group — it is the resource-name wildcard the simulator expects, not a
region/account wildcard.

Region and account are resolved to *real* values, never a wildcard:

* ``--region``: explicit ``--region`` option, else ``AWS_REGION`` /
  ``AWS_DEFAULT_REGION``, else the local AWS CLI default
  (``aws configure get region``). If none resolve, the script fails clearly.
* ``--account-id``: explicit ``--account-id`` option, else a read-only
  ``aws sts get-caller-identity --query Account`` call. If it cannot resolve,
  the script fails with an actionable message.
* ``--partition``: optional, defaults to ``aws``.

Embedding ``*`` in the region or account field of ``--resource-arns`` is not a
documented all-resources shortcut for the simulator, so it is never used as a
silent default. Explicit ``--region`` / ``--account-id`` overrides are honored
verbatim for callers deliberately testing another account or region.

Example
-------
::

    python3 simulate_cloudwatch_logs_policy.py policy.json my-log-group
    python3 simulate_cloudwatch_logs_policy.py policy.json my-log-group \\
        --partition aws --region us-east-1 --account-id 123456789012

AWS credentials must already be available to the AWS CLI (via environment,
shared credentials file, SSO, or instance/role metadata). This script does not
manage, prompt for, or transmit credentials, and it never prints the policy
contents.

Exit status is non-zero when inputs are invalid or an AWS CLI call fails.
"""

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Dict, Iterable, List, Optional, Tuple, cast

# Maximum policy file size accepted (bytes). IAM policy documents are capped at
# 6 144 bytes by the service; 64 KiB is a generous local limit that prevents an
# accidentally large file from being read entirely into memory.
_MAX_POLICY_FILE_BYTES = 64 * 1024

# Timeout (seconds) for each AWS CLI subprocess call.  Prevents a stalled
# credential refresh or network hang from blocking the tool indefinitely.
_SUBPROCESS_TIMEOUT = 60

# Allowlist patterns for ARN structural fields.  A blocklist on forbidden
# characters (e.g. ':' and '/') still passes wildcards, typos, and truncated
# values that produce silently misleading simulation output.  Allowlists make
# the accepted set explicit.
_PARTITION_RE = re.compile(r"\Aaws(?:-[a-z0-9]+)*\Z")
_REGION_RE    = re.compile(r"\A[a-z]{2}(?:-[a-z]+)+-[0-9]\Z")
_ACCOUNT_RE   = re.compile(r"\A[0-9]{12}\Z")

# CloudWatch Logs log group names may only contain letters, digits, and the
# characters underscore (_), hyphen (-), slash (/), dot (.), and hash (#).
# See: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/
#      API_CreateLogGroup.html (logGroupName pattern: [\.\-_/#A-Za-z0-9]+)
_LOG_GROUP_NAME_RE = re.compile(r'^[A-Za-z0-9_./#-]+$')

# Resolve the `aws` binary once at import time.  Using an absolute path means
# every subprocess call uses the same executable regardless of later PATH
# mutations, preventing a writable earlier PATH entry from substituting a
# different binary after startup.
_AWS_BIN: Optional[str] = shutil.which("aws")

# CloudWatch Logs IAM actions, sourced from the AWS Service Authorization
# Reference (see the "## Sources" section at the end of this file). The list
# below merges both the API-invocable actions and the permission-only actions
# verbatim, preserving exact capitalization. It is deduplicated and sorted
# deterministically at load time so the output ordering is stable and any
# accidental duplicate in the source list is harmless.
_RAW_LOGS_ACTIONS: Tuple[str, ...] = (
    "logs:AssociateKmsKey",
    "logs:AssociateSourceToS3TableIntegration",
    "logs:CancelExportTask",
    "logs:CancelImportTask",
    "logs:CreateDelivery",
    "logs:CreateExportTask",
    "logs:CreateImportTask",
    "logs:CreateLogAnomalyDetector",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:CreateLookupTable",
    "logs:CreateScheduledQuery",
    "logs:DeleteAccountPolicy",
    "logs:DeleteDataProtectionPolicy",
    "logs:DeleteDelivery",
    "logs:DeleteDeliveryDestination",
    "logs:DeleteDeliveryDestinationPolicy",
    "logs:DeleteDeliverySource",
    "logs:DeleteDestination",
    "logs:DeleteIndexPolicy",
    "logs:DeleteIntegration",
    "logs:DeleteLogAnomalyDetector",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "logs:DeleteLookupTable",
    "logs:DeleteMetricFilter",
    "logs:DeleteQueryDefinition",
    "logs:DeleteResourcePolicy",
    "logs:DeleteRetentionPolicy",
    "logs:DeleteScheduledQuery",
    "logs:DeleteSubscriptionFilter",
    "logs:DeleteSyslogConfiguration",
    "logs:DeleteTransformer",
    "logs:DescribeAccountPolicies",
    "logs:DescribeConfigurationTemplates",
    "logs:DescribeDeliveries",
    "logs:DescribeDeliveryDestinations",
    "logs:DescribeDeliverySources",
    "logs:DescribeDestinations",
    "logs:DescribeExportTasks",
    "logs:DescribeFieldIndexes",
    "logs:DescribeImportTaskBatches",
    "logs:DescribeImportTasks",
    "logs:DescribeIndexPolicies",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:DescribeLookupTables",
    "logs:DescribeMetricFilters",
    "logs:DescribeQueries",
    "logs:DescribeQueryDefinitions",
    "logs:DescribeResourcePolicies",
    "logs:DescribeSubscriptionFilters",
    "logs:DisassociateKmsKey",
    "logs:DisassociateSourceFromS3TableIntegration",
    "logs:FilterLogEvents",
    "logs:GetDataProtectionPolicy",
    "logs:GetDelivery",
    "logs:GetDeliveryDestination",
    "logs:GetDeliveryDestinationPolicy",
    "logs:GetDeliverySource",
    "logs:GetIntegration",
    "logs:GetLogAnomalyDetector",
    "logs:GetLogEvents",
    "logs:GetLogFields",
    "logs:GetLogGroupFields",
    "logs:GetLogRecord",
    "logs:GetLookupTable",
    "logs:GetQueryResults",
    "logs:GetScheduledQuery",
    "logs:GetScheduledQueryHistory",
    "logs:GetStorageTierPolicy",
    "logs:GetTransformer",
    "logs:ListAggregateLogGroupSummaries",
    "logs:ListAnomalies",
    "logs:ListIntegrations",
    "logs:ListLogAnomalyDetectors",
    "logs:ListLogGroups",
    "logs:ListLogGroupsForQuery",
    "logs:ListScheduledQueries",
    "logs:ListSourcesForS3TableIntegration",
    "logs:ListSyslogConfigurations",
    "logs:ListTagsForResource",
    "logs:ListTagsLogGroup",
    "logs:PutAccountPolicy",
    "logs:PutBearerTokenAuthentication",
    "logs:PutDataProtectionPolicy",
    "logs:PutDeliveryDestination",
    "logs:PutDeliveryDestinationPolicy",
    "logs:PutDeliverySource",
    "logs:PutDestination",
    "logs:PutDestinationPolicy",
    "logs:PutIndexPolicy",
    "logs:PutIntegration",
    "logs:PutLogEvents",
    "logs:PutLogGroupDeletionProtection",
    "logs:PutMetricFilter",
    "logs:PutQueryDefinition",
    "logs:PutResourcePolicy",
    "logs:PutRetentionPolicy",
    "logs:PutStorageTierPolicy",
    "logs:PutSubscriptionFilter",
    "logs:PutSyslogConfiguration",
    "logs:PutTransformer",
    "logs:StartLiveTail",
    "logs:StartQuery",
    "logs:StopQuery",
    "logs:TagLogGroup",
    "logs:TagResource",
    "logs:TestMetricFilter",
    "logs:TestTransformer",
    "logs:UntagLogGroup",
    "logs:UntagResource",
    "logs:UpdateAnomaly",
    "logs:UpdateDeliveryConfiguration",
    "logs:UpdateLogAnomalyDetector",
    "logs:UpdateLookupTable",
    "logs:UpdateScheduledQuery",
    # Permission-only actions (grantable in IAM policies, no direct API call).
    "logs:CallWithBearerToken",
    "logs:CreateLogDelivery",
    "logs:DeleteLogDelivery",
    "logs:DeletePipelineRule",
    "logs:GetLogDelivery",
    "logs:IntegrateWithS3Table",
    "logs:Link",
    "logs:ListEntitiesForLogGroup",
    "logs:ListLogDeliveries",
    "logs:ListLogGroupsForEntity",
    "logs:ProcessWithPipeline",
    "logs:PutPipelineRule",
    "logs:StopLiveTail",
    "logs:Unmask",
    "logs:UpdateLogDelivery",
)

# Deterministic, deduplicated, sorted action list. IAM simulate-custom-policy
# requires concrete action names; "logs:*" is not accepted in --action-names.
LOGS_ACTIONS: Tuple[str, ...] = tuple(sorted(set(_RAW_LOGS_ACTIONS)))

# Number of action names sent per simulate-custom-policy call. 100 is a
# conservative default that keeps each CLI invocation small and its output
# manageable; callers may raise or lower it with --batch-size. Results from
# every batch are merged so each action appears exactly once per resource.
DEFAULT_BATCH_SIZE = 100

# Upper bound for --batch-size. IAM SimulateCustomPolicy accepts at most 128
# ActionNames per call, so batches larger than this are rejected up front.
MAX_BATCH_SIZE = 128


class SimulationError(Exception):
    """Raised when an AWS CLI simulation call fails for a resource."""


def _validate_arn_field(value: str, field: str) -> None:
    """Raise ``SystemExit`` if ``value`` does not match the expected ARN field pattern.

    Uses allowlist regexes rather than a blocklist so that wildcards, typos,
    truncated values, and other unexpected inputs are caught before they produce
    a silently misleading simulation table.
    """
    patterns = {
        "partition": (_PARTITION_RE, "expected e.g. 'aws', 'aws-us-gov', 'aws-iso'"),
        "region":    (_REGION_RE,    "expected e.g. 'us-east-1', 'eu-west-2'"),
        "account-id": (_ACCOUNT_RE,  "expected exactly 12 digits"),
    }
    pattern, hint = patterns.get(field, (None, ""))
    if pattern and not pattern.match(value):
        raise SystemExit(
            f"error: {field} '{value}' is not a valid AWS {field} ({hint})."
        )


def _validate_log_group_name(name: str) -> None:
    """Raise ``SystemExit`` if ``name`` is not a valid CloudWatch Logs log group name.

    CWL log group names match the pattern ``[\\.\-_/#A-Za-z0-9]+`` (1–512 chars).
    Rejecting names outside this set prevents newlines, null bytes, or other
    control characters from being embedded in the ARN string passed to IAM.
    """
    if not name:
        raise SystemExit("error: log group name must not be empty.")
    if len(name) > 512:
        raise SystemExit(
            f"error: log group name is {len(name)} characters; "
            "CloudWatch Logs log group names must be 512 characters or fewer."
        )
    if not _LOG_GROUP_NAME_RE.match(name):
        raise SystemExit(
            f"error: log group name '{name}' contains characters not allowed by "
            "CloudWatch Logs. Log group names may only contain letters, digits, "
            "and the characters _ - / . # ."
        )


def build_resource_arns(
    partition: str, region: str, account_id: str, log_group_name: str
) -> Tuple[str, str]:
    """Return ``(log_stream_arn, log_group_arn)`` in fully-qualified form.

    Validates that ``partition``, ``region``, and ``account_id`` contain no
    colon or slash characters, and that ``log_group_name`` matches the
    CloudWatch Logs character set (``[A-Za-z0-9_./#-]+``, 1–512 chars).
    Rejecting names outside this set prevents control characters such as
    newlines or null bytes from being embedded in the ARN string passed to IAM.

    The log-stream ARN is returned first because it is simulated first.
    """
    _validate_arn_field(partition, "partition")
    _validate_arn_field(region, "region")
    _validate_arn_field(account_id, "account-id")
    _validate_log_group_name(log_group_name)
    log_group_arn = f"arn:{partition}:logs:{region}:{account_id}:log-group:{log_group_name}"
    log_stream_arn = f"{log_group_arn}:log-stream:*"
    return log_stream_arn, log_group_arn


def validate_policy(policy_path: str) -> str:
    """Validate ``policy_path`` as JSON and return its document text.

    The file is parsed locally to fail fast on malformed input. The returned
    string is the exact policy-document text, suitable for insertion as a
    single element of the ``PolicyInputList`` array in a SimulateCustomPolicy
    request (that field is an array of policy-document *strings*, not nested
    JSON objects). The text is written only into a short-lived request file at
    call time; it is never placed on the command line, logged, or printed.
    """
    abs_path = os.path.abspath(policy_path)
    # stat() + S_ISREG check: rejects /dev/zero, FIFOs, and other non-regular
    # files before opening.  The theoretical TOCTOU window between stat() and
    # open() is accepted for this tool — it is a local dev script, not a daemon,
    # and the cross-platform compatibility of os.stat() + open() is preferred
    # over the POSIX-only O_NONBLOCK + fcntl approach.
    try:
        st = os.stat(abs_path)
    except OSError as exc:
        raise SystemExit(f"error: cannot read policy file '{policy_path}': {exc}")
    if not stat.S_ISREG(st.st_mode):
        raise SystemExit(
            f"error: '{policy_path}' is not a regular file. "
            "Provide a plain JSON file containing the IAM policy document."
        )
    if st.st_size > _MAX_POLICY_FILE_BYTES:
        raise SystemExit(
            f"error: policy file '{policy_path}' is {st.st_size} bytes, "
            f"which exceeds the {_MAX_POLICY_FILE_BYTES}-byte limit. "
            "IAM policies are at most 6 144 bytes; check that you supplied "
            "the right file."
        )
    try:
        with open(abs_path, "r", encoding="utf-8") as handle:
            # Cap the read so a file grown after stat() cannot exhaust memory.
            content = handle.read(_MAX_POLICY_FILE_BYTES + 1)
    except (OSError, UnicodeError) as exc:
        raise SystemExit(f"error: cannot read policy file '{policy_path}': {exc}")
    if len(content) > _MAX_POLICY_FILE_BYTES:
        raise SystemExit(
            f"error: policy file '{policy_path}' exceeds the "
            f"{_MAX_POLICY_FILE_BYTES}-byte limit. "
            "IAM policies are at most 6 144 bytes; check that you supplied "
            "the right file."
        )

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        # Report the location only, never the policy body.
        raise SystemExit(
            f"error: policy file '{policy_path}' is not valid JSON "
            f"(line {exc.lineno}, column {exc.colno}): {exc.msg}"
        )
    # Require the document to be a JSON object with a Statement key.  This
    # stops the tool from transmitting an arbitrary JSON file (e.g. a credential
    # cache) to the IAM SimulateCustomPolicy API.
    if not isinstance(parsed, dict) or "Statement" not in parsed:
        raise SystemExit(
            f"error: policy file '{policy_path}' does not look like an IAM "
            "policy document (expected a JSON object with a 'Statement' key)."
        )
    return content


def _sanitize_stderr(stderr: Optional[str], policy_text: str = "") -> Optional[str]:
    """Return a concise, policy-free summary of AWS CLI ``stderr``.

    Uses two complementary filters so that partial or reformatted echoes of
    the policy body cannot leak through:

    1. Allowlist structural filter: drop any line containing ``{``, ``}``, or
       a known IAM policy keyword (``Statement``, ``Effect``, ``Action``,
       ``Resource``, ``Version``).  This catches the common case where the
       CLI echoes the full JSON body on one line.

    2. Substring filter: additionally drop any line that appears verbatim as
       a substring of ``policy_text``.  This catches reformatted/wrapped
       echoes where bare values (ARNs, Sid strings, Condition values) land on
       their own line without an accompanying brace or keyword.

    Safe AWS CLI error class names (e.g. ``InvalidInputException``) pass both
    filters and are preserved for diagnostics.
    Returns ``None`` when there is nothing useful to report.
    """
    if not stderr:
        return None
    text = stderr.strip()
    if not text:
        return None
    # Token-level redaction: redact any long verbatim token from the policy
    # that appears inline within a stderr line (e.g. "Error near <ARN> at offset 12").
    # This runs before the line filter so inline echoes are masked even when the
    # containing line has no brace or policy keyword.
    if policy_text:
        for token in {t for t in policy_text.split() if len(t) > 30}:
            text = text.replace(token, "<redacted>")
    _POLICY_INDICATORS = frozenset(("{", "}", "Statement", "Effect", "Action", "Resource", "Version"))
    safe_lines = [
        line.strip() for line in text.splitlines()
        if line.strip()
        and not any(ind in line for ind in _POLICY_INDICATORS)
        and (not policy_text or line.strip() not in policy_text)
    ]
    message = safe_lines[-1] if safe_lines else "(no safe detail available)"
    if len(message) > 500:
        message = message[:500] + " …(truncated)"
    return message


def _run_aws(args: List[str]) -> Optional[str]:
    """Run a read-only ``aws`` command; return trimmed stdout or ``None``.

    Returns ``None`` (rather than raising) when the CLI is missing, exits
    non-zero, or times out, so callers can fall through to the next resolution
    source or raise a tailored error. No output is printed here.

    Uses the absolute ``_AWS_BIN`` path resolved at import time to prevent a
    writable PATH entry from substituting a different executable after startup.
    """
    if _AWS_BIN is None:
        return None
    try:
        completed = subprocess.run(
            [_AWS_BIN, *args],
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    value = (completed.stdout or "").strip()
    return value or None


def resolve_region(explicit: Optional[str]) -> str:
    """Resolve a real AWS region, or exit with an actionable error.

    Order: explicit ``--region`` -> ``AWS_REGION`` -> ``AWS_DEFAULT_REGION`` ->
    local AWS CLI default (``aws configure get region``). Never falls back to a
    wildcard.
    """
    if explicit:
        return explicit
    for env_var in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        value = os.environ.get(env_var)
        if value:
            return value
    # `aws configure get region` reads local config only; no network call.
    value = _run_aws(["configure", "get", "region"])
    if value:
        return value
    raise SystemExit(
        "error: could not resolve an AWS region. Pass --region <region>, set "
        "AWS_REGION or AWS_DEFAULT_REGION, or configure a default region with "
        "'aws configure set region <region>'."
    )


def resolve_account_id(explicit: Optional[str]) -> str:
    """Resolve a real AWS account id, or exit with an actionable error.

    Order: explicit ``--account-id`` -> read-only
    ``aws sts get-caller-identity --query Account``. Never falls back to a
    wildcard.
    """
    if explicit:
        return explicit
    value = _run_aws(["sts", "get-caller-identity", "--query", "Account", "--output", "text"])
    # `aws ... --output text` prints the string "None" when the field is
    # absent; treat that as unresolved rather than a real account id.
    if value and value != "None":
        return value
    raise SystemExit(
        "error: could not resolve the AWS account id. Pass --account-id "
        "<account-id>, or ensure the AWS CLI is authenticated so "
        "'aws sts get-caller-identity' succeeds."
    )


def _chunked(items: Tuple[str, ...], size: int) -> Iterable[List[str]]:
    """Yield successive lists of at most ``size`` items."""
    for start in range(0, len(items), size):
        yield list(items[start : start + size])



def simulate_resource(
    policy_text: str,
    resource_arn: str,
    actions: Tuple[str, ...],
    batch_size: int,
) -> Dict[str, Dict[str, object]]:
    """Simulate all ``actions`` against a single ``resource_arn``.

    For each batch a temporary JSON request file is written containing the
    API-shaped fields ``PolicyInputList`` (``[policy_text]``), ``ActionNames``,
    and ``ResourceArns``, and passed via ``--cli-input-json file://<file>`` so
    the policy body never appears in argv. The request file is created inside a
    private temporary directory (mode 0o700) to prevent a local user on a shared
    system from substituting the file between write and read. The directory is
    removed in a ``finally`` block on every path.
    Returns a mapping ``action -> {"decision": str, "missing": List[str]}``,
    merged across batches so each action appears exactly once.
    """
    if _AWS_BIN is None:
        raise SimulationError(
            "the 'aws' CLI was not found on PATH; install and configure "
            "the AWS CLI before running this script"
        )

    results: Dict[str, Dict[str, object]] = {}
    for batch in _chunked(actions, batch_size):
        request = {
            "PolicyInputList": [policy_text],
            "ActionNames": batch,
            "ResourceArns": [resource_arn],
        }
        # Use a private temp directory (mode 0o700) so only the calling user
        # can read or write the request file, preventing a local-user TOCTOU
        # substitution on shared systems.
        tmp_dir = tempfile.mkdtemp(prefix="iam-sim-", suffix="-dir")
        try:
            # NamedTemporaryFile with delete=False gives us a secure temp file
            # that works on all platforms.  On POSIX the file is created with
            # 0600 permissions; on Windows it relies on the directory ACL
            # (mkdtemp creates a directory only the current user can access).
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                dir=tmp_dir,
                delete=False,
                encoding="utf-8",
            ) as handle:
                request_path = handle.name
                json.dump(request, handle)

            command = [
                _AWS_BIN,
                "iam",
                "simulate-custom-policy",
                "--cli-input-json",
                f"file://{request_path}",
                "--output",
                "json",
                "--no-cli-pager",
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    shell=False,
                    check=False,
                    timeout=_SUBPROCESS_TIMEOUT,
                )
            except FileNotFoundError:
                raise SimulationError(
                    "the 'aws' CLI was not found on PATH; install and configure "
                    "the AWS CLI before running this script"
                )
            except subprocess.TimeoutExpired:
                raise SimulationError(
                    f"'aws iam simulate-custom-policy' timed out after "
                    f"{_SUBPROCESS_TIMEOUT}s for resource '{resource_arn}'. "
                    "Check your network connectivity and AWS CLI credentials."
                )

            if completed.returncode != 0:
                detail = _sanitize_stderr(completed.stderr, policy_text)
                message = (
                    f"'aws iam simulate-custom-policy' failed for resource "
                    f"'{resource_arn}' (exit {completed.returncode})"
                )
                if detail:
                    message += f": {detail}"
                raise SimulationError(message)

            try:
                payload = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                raise SimulationError(
                    f"could not parse AWS CLI JSON output for resource "
                    f"'{resource_arn}': {exc}"
                )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        for entry in payload.get("EvaluationResults", []):
            action_name = entry.get("EvalActionName", "<unknown>")
            results[action_name] = {
                "decision": entry.get("EvalDecision", "unknown"),
                "missing": list(entry.get("MissingContextValues") or []),
            }
    return results


def _format_table(
    actions: Tuple[str, ...],
    stream_results: Dict[str, Dict[str, object]],
    group_results: Dict[str, Dict[str, object]],
) -> str:
    """Render a deterministic ``Action | LogStream | LogGroup`` table.

    A trailing ``*`` on a decision marks that the action reported
    MissingContextValues for that resource; the keys are listed below the
    table. Policy contents are never included.

    The value ``notSimulated`` (rather than ``-``) is used when an action was
    not returned by the simulator at all, so it is distinguishable from an
    explicit ``implicitDeny`` result.
    """
    header = ("Action", "LogStream", "LogGroup")

    def cell(results: Dict[str, Dict[str, object]], action: str) -> str:
        record = results.get(action)
        if record is None:
            return "notSimulated"
        decision = str(record["decision"])
        return decision + ("*" if record["missing"] else "")

    rows = [
        (action, cell(stream_results, action), cell(group_results, action)) for action in actions
    ]

    widths = [len(header[i]) for i in range(3)]
    for row in rows:
        for i in range(3):
            widths[i] = max(widths[i], len(row[i]))

    def fmt(row: Tuple[str, str, str]) -> str:
        return "  ".join(row[i].ljust(widths[i]) for i in range(3)).rstrip()

    lines = [fmt(header), "  ".join("-" * widths[i] for i in range(3))]
    lines.extend(fmt(row) for row in rows)

    missing_notes: List[str] = []
    for action in actions:
        for label, results in (("LogStream", stream_results), ("LogGroup", group_results)):
            record = results.get(action)
            if record and record["missing"]:
                keys = ", ".join(cast(List[str], record["missing"]))
                missing_notes.append(f"  {action} [{label}]: {keys}")
    if missing_notes:
        lines.append("")
        lines.append("* MissingContextValues (decision depends on unset condition keys):")
        lines.extend(missing_notes)

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    epilog = f"""\
Resource evaluation order:
  1. log-stream ARN  arn:{{partition}}:logs:{{region}}:{{account}}:log-group:{{NAME}}:log-stream:*
  2. log-group  ARN  arn:{{partition}}:logs:{{region}}:{{account}}:log-group:{{NAME}}
  The log-stream ARN is simulated first, then the log-group ARN. Each output
  row shows the allow/deny decision for both resource forms.

Valid ARN forms and shorthand:
  The shorthand 'log-group:NAME:log-stream:*' is NOT a valid AWS ARN. This
  script always fills in the logs:{{region}}:{{account}} fields and builds the
  fully-qualified ARNs above. The trailing 'log-stream:*' is a wildcard over
  log-stream NAMES within the group, not over the region or account.

Region and account resolution (never a wildcard):
  region   --region, else AWS_REGION / AWS_DEFAULT_REGION, else
           'aws configure get region' (local config, no network call).
  account  --account-id, else a read-only 'aws sts get-caller-identity'.
  The script exits with an actionable error if either cannot resolve to a
  real value.

Actions and batching:
  Simulates all {len(LOGS_ACTIONS)} concrete logs: IAM actions. IAM
  SimulateCustomPolicy requires concrete action names, so 'logs:*' is not
  accepted. Actions are sent in batches of --batch-size per call (default
  {DEFAULT_BATCH_SIZE}, valid range 1-{MAX_BATCH_SIZE}) and the results are
  merged, so each action appears exactly once per resource.

AWS requirements:
  The AWS CLI must be installed and authenticated (environment, shared
  credentials file, SSO, or instance/role metadata). The caller needs
  iam:SimulateCustomPolicy, plus sts:GetCallerIdentity only when --account-id
  is omitted. This script performs no AWS write operations and never prints
  the policy contents.

Example:
  python3 simulate_cloudwatch_logs_policy.py policy.json my-log-group \\
      --region us-east-1 --account-id 123456789012
"""

    parser = argparse.ArgumentParser(
        prog="simulate_cloudwatch_logs_policy.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Simulate a custom IAM policy against every CloudWatch Logs IAM "
            "action for a log-stream ARN and a log-group ARN using "
            "'aws iam simulate-custom-policy'. Standard-library only; shells out "
            "to the authenticated AWS CLI and reads no credentials directly."
        ),
        epilog=epilog,
    )
    parser.add_argument("policy_file", help="Path to a JSON IAM policy document.")
    parser.add_argument("log_group_name", help="CloudWatch Logs log-group name.")
    parser.add_argument(
        "--partition", default="aws", help="AWS partition for the ARN (default: aws)."
    )
    parser.add_argument(
        "--region",
        default=None,
        help=(
            "AWS region for the ARN. Resolves from this option, else "
            "AWS_REGION/AWS_DEFAULT_REGION, else 'aws configure get region'. "
            "Fails if no real region is available."
        ),
    )
    parser.add_argument(
        "--account-id",
        default=None,
        help=(
            "AWS account id for the ARN. Resolves from this option, else a "
            "read-only 'aws sts get-caller-identity'. Fails if it cannot resolve."
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=(
            "Number of action names per simulate-custom-policy call "
            f"(default: {DEFAULT_BATCH_SIZE}, valid range: 1-{MAX_BATCH_SIZE}). "
            f"IAM SimulateCustomPolicy accepts at most {MAX_BATCH_SIZE} "
            "ActionNames per call."
        ),
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.batch_size < 1 or args.batch_size > MAX_BATCH_SIZE:
        parser.error(
            f"--batch-size must be between 1 and {MAX_BATCH_SIZE} "
            f"(IAM SimulateCustomPolicy accepts at most {MAX_BATCH_SIZE} "
            "ActionNames per call)"
        )

    # Check for the aws binary after argument validation so that argument
    # errors (e.g. invalid --batch-size) are always reported via argparse
    # even on hosts where the AWS CLI is not installed.
    if _AWS_BIN is None:
        print(
            "error: the 'aws' CLI was not found on PATH. Install and configure "
            "the AWS CLI before running this script.",
            file=sys.stderr,
        )
        return 1

    # Validate the policy locally, then carry it inside a per-batch
    # --cli-input-json request file so the JSON body never appears in argv /
    # /proc/<pid>/cmdline.
    policy_text = validate_policy(args.policy_file)

    # Resolve real region/account values; each raises SystemExit with an
    # actionable message rather than silently using a wildcard.
    region = resolve_region(args.region)
    account_id = resolve_account_id(args.account_id)

    log_stream_arn, log_group_arn = build_resource_arns(
        args.partition, region, account_id, args.log_group_name
    )

    # Log-stream is simulated before log-group, per requirement.
    try:
        stream_results = simulate_resource(
            policy_text, log_stream_arn, LOGS_ACTIONS, args.batch_size
        )
    except SimulationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        group_results = simulate_resource(policy_text, log_group_arn, LOGS_ACTIONS, args.batch_size)
    except SimulationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"LogStream ARN: {log_stream_arn}")
    print(f"LogGroup  ARN: {log_group_arn}")
    print(f"Actions simulated: {len(LOGS_ACTIONS)}")
    print()
    print(_format_table(LOGS_ACTIONS, stream_results, group_results))
    return 0


if __name__ == "__main__":
    sys.exit(main())

# ============================================================================
# ## Sources
#
# - [Actions, resources, and condition keys for Amazon CloudWatch Logs]
#   (https://docs.aws.amazon.com/service-authorization/latest/reference/list_logs.html)
#   — full `logs:` IAM action list, including permission-only actions.
#   Accessed 2026-09-01.
# - [IAM SimulateCustomPolicy API reference]
#   (https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html)
#   — concrete action names required; ActionNames limit (max 128 per call);
#   EvaluationResults / EvalDecision / MissingContextValues response shape.
#   Accessed 2026-09-01.
# - [aws iam simulate-custom-policy CLI reference]
#   (https://docs.aws.amazon.com/cli/latest/reference/iam/simulate-custom-policy.html)
#   — --cli-input-json, --policy-input-list, --action-names, --resource-arns.
#   --policy-input-list is list-valued and does not expand a file:// URI into
#   its elements; the full request is supplied via --cli-input-json instead.
#   Accessed 2026-09-01.
# - [AWS CLI: generate and use a JSON input (--cli-input-json)]
#   (https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-parameters-file.html)
#   — global --cli-input-json file://<request.json> supplies a complete,
#   API-shaped request (PolicyInputList / ActionNames / ResourceArns here).
#   Accessed 2026-09-01.
# - [CloudWatch Logs resource ARN formats]
#   (https://docs.aws.amazon.com/service-authorization/latest/reference/list_logs.html)
#   — log-group and log-stream ARN patterns
#   (arn:{partition}:logs:{region}:{account}:log-group:{name}[:log-stream:*]).
#   Accessed 2026-09-01.
# ============================================================================
