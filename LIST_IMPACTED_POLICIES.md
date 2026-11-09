# List IAM Policies Impacted by the CloudWatch Logs Log Group ARN Format Enforcement

AWS CloudWatch Logs is enforcing the standard log group ARN format for IAM
authorization. Policies that use the old format with a trailing `:*` (for
example, `arn:aws:logs:us-east-1:123456789012:log-group:MyGroup:*`) will stop
taking effect for log-group-level actions after enforcement begins.

This command lists only the policies affected by this change: statements
that apply a log-group-level action to an old-format `log-group:<name>:*` ARN.
Policies that already use the standard format are not reported, for example
`log-group:*` or `log-group:MyGroup` for log-group actions, or
`log-group:MyGroup:log-stream:*` for log-stream actions. Neither are
old-format ARNs whose statements grant only log-stream actions, such as
`logs:CreateLogStream` and `logs:PutLogEvents` on `log-group:MyGroup:*`. That
pattern keeps working, because `log-group:MyGroup:*` still matches the group's
log-stream ARNs.

## Prerequisites

- AWS CLI v2, installed and authenticated
- [`jq`](https://jqlang.github.io/jq/) installed and on your `PATH`
- IAM permission: `iam:GetAccountAuthorizationDetails`

## Command

```bash
aws iam get-account-authorization-details \
  --filter LocalManagedPolicy Role User Group \
  --output json | jq -r '
  def arr: if type=="array" then . else [.] end;
  # Legacy log-group ARN: log-group:<name>:* (log-stream ARNs excluded).
  def legacy: test("^arn:aws[a-z0-9-]*:logs:[^:]*:[^:]*:log-group:[^:]*:\\*$");
  # Actions authorized against the log-group resource type (Service Authorization Reference).
  def group_actions: ["AssociateKmsKey","CreateExportTask","CreateLogAnomalyDetector",
    "CreateLogGroup","DeleteDataProtectionPolicy","DeleteLogGroup","DeleteMetricFilter",
    "DeleteRetentionPolicy","DeleteSubscriptionFilter","DeleteSyslogConfiguration",
    "DeleteTransformer","DescribeLogStreams","DescribeMetricFilters",
    "DescribeSubscriptionFilters","DisassociateKmsKey","FilterLogEvents",
    "GetDataProtectionPolicy","GetLogGroupFields","GetLogRecord","GetQueryResults",
    "GetTransformer","IntegrateWithDataset","ListTagsForResource","ListTagsLogGroup",
    "ProcessWithPipeline","PutBearerTokenAuthentication","PutDataProtectionPolicy",
    "PutLogGroupDeletionProtection","PutMetricFilter","PutRetentionPolicy",
    "PutSubscriptionFilter","PutSyslogConfiguration","PutTransformer","StartLiveTail",
    "StartQuery","TagLogGroup","TagResource","Unmask","UntagLogGroup","UntagResource"]
    | map("logs:" + .);
  # IAM action wildcard (* and ?) -> anchored, case-insensitive regex.
  def glob_re: "^" + (gsub("(?<c>[.+^$(){}|\\[\\]\\\\])"; "\\\(.c)")
    | gsub("\\*"; ".*") | gsub("\\?"; ".")) + "$";
  def matches($a): . as $p | $a | test($p | glob_re; "i");
  # Log-group-level actions granted (or denied) by a statement.
  def hits:
    if has("NotAction") then (.NotAction|arr) as $n
      | [group_actions[] | select(. as $a | all($n[]; matches($a)) | not)]
    else (.Action//[]|arr) as $p
      | [group_actions[] | select(. as $a | any($p[]; matches($a)))]
    end;

  # Scan one policy document, emitting "<Effect>\t<Field>\t<Arn>\t<actions>" lines.
  def scan:
    (.Statement|arr)[] | .Effect as $e | hits as $h
    | select($h|length>0)
    | ("Resource","NotResource") as $f
    | (.[$f]//empty|arr)[]
    | select(type=="string" and legacy)
    | "    \($e // "Unknown")\t\($f)\t\(.)\t\($h|length) log-group action(s), e.g. \($h[0:3]|join(", "))";

  # Print header then hits, only if the doc has any.
  def report($hdr; doc): [doc|scan] | select(length>0) | ($hdr, .[]);

  ( .Policies[]
    | report("MANAGED  \(.Arn)";
        (.PolicyVersionList[]|select(.IsDefaultVersion)|.Document)) ),
  ( .UserDetailList[]  | .Arn as $a | .UserPolicyList[]?
    | report("INLINE   \($a) [\(.PolicyName)]"; .PolicyDocument) ),
  ( .GroupDetailList[] | .Arn as $a | .GroupPolicyList[]?
    | report("INLINE   \($a) [\(.PolicyName)]"; .PolicyDocument) ),
  ( .RoleDetailList[]  | .Arn as $a | .RolePolicyList[]?
    | report("INLINE   \($a) [\(.PolicyName)]"; .PolicyDocument) )
'
```

## What it checks

- **`LocalManagedPolicy`** — customer-managed policies in your account (the
  default version of each). AWS-managed policies are not included.
- **Inline policies** attached to `User`, `Group`, and `Role` principals.
- Both the `Resource` and `NotResource` elements of every statement.
- A statement is flagged only when **both** of these are true:
  1. Its `Resource` or `NotResource` contains an old-format log group ARN,
     `log-group:<name>:*`. Here `<name>` can include wildcards, as in
     `log-group:*:*` or `log-group:/aws/lambda/*:*`. Log-stream ARNs
     (`...:log-stream:...`) and standard log group ARNs (`log-group:<name>`,
     `log-group:*`) are never flagged.
  2. Its `Action` or `NotAction` covers at least one **log-group-level action**:
     an action that the
     [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_logs.html)
     authorizes against the `log-group` resource type, such as
     `logs:CreateLogGroup`, `logs:PutRetentionPolicy`, `logs:DescribeLogStreams`,
     `logs:FilterLogEvents`, or `logs:StartQuery`. Action wildcards (`logs:*`,
     `logs:Put*`, `*`, `?`) are expanded case-insensitively. A `NotAction` counts
     when it does not exclude every log-group-level action. Statements that grant
     only log-stream-level actions (`logs:CreateLogStream`,
     `logs:DeleteLogStream`, `logs:GetLogEvents`, `logs:PutLogEvents`) are not
     flagged.
- Both `Allow` and `Deny` statements are reported. A `Deny` on an old-format ARN
  stops blocking log-group-level actions once enforcement begins.
- The partition matcher (`aws[a-z0-9-]*`) covers `aws`, `aws-cn`, and
  `aws-us-gov`.
- The log-group-level action list is embedded in the command (`group_actions`).
  If CloudWatch Logs adds new log-group-level actions, add them to this list.
- Condition keys are not evaluated, so a statement can be flagged even if its
  conditions would never match.

## Sample output

Each impacted policy prints a header line, then one indented line per flagged
ARN. Each line shows the statement `Effect`, the field (`Resource` or
`NotResource`), the old-format ARN, and the log-group-level actions that the
statement covers:

```
MANAGED  arn:aws:iam::123456789012:policy/MyLogsPolicy
    Allow	Resource	arn:aws:logs:us-east-1:123456789012:log-group:MyGroup:*	1 log-group action(s), e.g. logs:CreateLogGroup
INLINE   arn:aws:iam::123456789012:role/MyRole [InlineLogsAccess]
    Allow	Resource	arn:aws:logs:us-east-1:123456789012:log-group:AppLogs:*	40 log-group action(s), e.g. logs:AssociateKmsKey, logs:CreateExportTask, logs:CreateLogAnomalyDetector
```

If the command produces no output, none of the account's customer-managed or
inline policies are affected by the enforcement.

## Next steps

For each impacted policy:

1. Review the flagged statement, its `Resource`/`NotResource` ARN, and the
   log-group-level actions listed.
2. Grant the log-group-level actions on the standard log group ARN (no trailing
   `:*`, for example `log-group:MyGroup` or `log-group:*`). Keep
   `log-group:MyGroup:*` or `log-group:MyGroup:log-stream:*` only for
   log-stream-level actions. A common fix is to split the statement in two: one
   for log-group actions and one for log-stream actions.
3. Use [`simulate_cloudwatch_logs_policy.py`](README.md) to confirm the updated
   policy still grants the required actions under the standard log group ARN
   format.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
