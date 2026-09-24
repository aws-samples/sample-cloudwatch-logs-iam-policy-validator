# List IAM Policies Impacted by the CloudWatch Logs Log Group ARN Format Enforcement

AWS CloudWatch Logs is enforcing the standard log group ARN format for IAM
authorization. Policies that use the old format with a trailing `:*` (for
example, `arn:aws:logs:us-east-1:123456789012:log-group:MyGroup:*`) will stop
taking effect for log-group-level actions after enforcement begins.

This script helps you find the policies potentially impacted by this change.

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
  def old: test("^arn:aws[a-z0-9-]*:logs:[^:]*:[^:]*:log-group:.*(:\\*$|:log-stream:)");

  # Scan one policy document, emitting indented "<Effect>\t<Field>\t<Arn>" lines.
  def scan:
    (.Statement|arr)[] | .Effect as $e
    | ("Resource","NotResource") as $f
    | (.[$f]//empty|arr)[]
    | select(type=="string" and old)
    | "    \($e // "Unknown")\t\($f)\t\(.)";

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
- An ARN is flagged when it targets a CloudWatch Logs `log-group:` resource and
  ends in `:*` (the old log-group format) or contains `:log-stream:`. The
  partition matcher (`aws[a-z0-9-]*`) covers `aws`, `aws-cn`, and `aws-us-gov`.

## Sample output

Each impacted policy prints a header line followed by one indented line per
matching ARN, showing the statement `Effect`, the field (`Resource` or
`NotResource`), and the offending ARN:

```
MANAGED  arn:aws:iam::123456789012:policy/MyLogsPolicy
    Allow	Resource	arn:aws:logs:us-east-1:123456789012:log-group:MyGroup:*
INLINE   arn:aws:iam::123456789012:role/MyRole [InlineLogsAccess]
    Allow	Resource	arn:aws:logs:us-east-1:123456789012:log-group:AppLogs:log-stream:*
```

If the command produces no output, no customer-managed or inline policies in the
account use the old log group ARN format.

## Next steps

For each impacted policy:

1. Review the flagged statement and its `Resource`/`NotResource` ARN.
2. Update the ARN to the standard log group format (remove the trailing `:*` for
   log-group-level actions), keeping any log-stream ARNs only where
   log-stream-level actions are intended.
3. Use [`simulate_cloudwatch_logs_policy.py`](README.md) to confirm the updated
   policy still grants the required actions under the standard log group ARN
   format.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
