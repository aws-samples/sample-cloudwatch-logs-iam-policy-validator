# CloudWatch Logs IAM Policy Validator

A Python script that simulates an IAM policy against every CloudWatch Logs API action for both log-group and log-stream ARN formats using `aws iam simulate-custom-policy`.

Use this script to verify that your IAM policies work correctly with the **standard log group ARN format** (without a trailing `:*`) before AWS CloudWatch Logs begins enforcing it.

## Background

AWS CloudWatch Logs is enforcing the standard log group ARN format for IAM authorization. Policies that use the old format with a trailing `:*` (for example, `arn:aws:logs:us-east-1:123456789012:log-group:MyGroup:*`) will stop taking effect for log-group-level actions after enforcement begins.

This script helps you verify your policies before that date.

## Prerequisites

- Python 3.8 or later
- AWS CLI v2, installed and authenticated
- IAM permission: `iam:SimulateCustomPolicy`
- IAM permission: `sts:GetCallerIdentity` (only if you omit `--account-id`)

## Usage

```bash
python3 simulate_cloudwatch_logs_policy.py POLICY_FILE LOG_GROUP_NAME \
    [--region REGION] [--account-id ACCOUNT_ID] [--partition PARTITION]
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `POLICY_FILE` | Yes | Path to a local JSON file containing the IAM policy document to test |
| `LOG_GROUP_NAME` | Yes | The CloudWatch Logs log group name to use in the simulated ARNs |
| `--region` | No | AWS region for the simulated ARNs. Defaults to `AWS_REGION`, `AWS_DEFAULT_REGION`, or your AWS CLI default |
| `--account-id` | No | AWS account ID for the simulated ARNs. Defaults to the result of `aws sts get-caller-identity` |
| `--partition` | No | AWS partition for the simulated ARNs. Defaults to `aws`. Use `aws-cn` for China regions or `aws-us-gov` for AWS GovCloud (US) |

### Example

Save your IAM policy to a file:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "logs:*",
      "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:MyLogGroup"
    }
  ]
}
```

Run the script:

```bash
python3 simulate_cloudwatch_logs_policy.py policy.json MyLogGroup \
    --region us-east-1 --account-id 123456789012
```

### Sample output

```
LogStream ARN: arn:aws:logs:us-east-1:123456789012:log-group:MyLogGroup:log-stream:*
LogGroup  ARN: arn:aws:logs:us-east-1:123456789012:log-group:MyLogGroup
Actions simulated: 40

Action                              LogStream     LogGroup
----------------------------------  ------------  ------------
logs:AssociateKmsKey                implicitDeny  allowed
logs:CreateExportTask               implicitDeny  allowed
logs:CreateLogGroup                 implicitDeny  allowed
logs:DeleteLogGroup                 implicitDeny  allowed
logs:PutRetentionPolicy             implicitDeny  allowed
logs:PutMetricFilter                implicitDeny  allowed
...
logs:CreateLogStream                allowed       implicitDeny
logs:PutLogEvents                   allowed       implicitDeny
logs:GetLogEvents                   allowed       implicitDeny
```

### Interpreting the results

- **`LogGroup` column shows `allowed`** — your policy grants that action on the standard log-group ARN format ✅
- **`LogGroup` column shows `implicitDeny`** — your policy does NOT grant that action on the standard log-group ARN. Update the `Resource` element of the relevant policy statement to include the standard log-group ARN format, then rerun the script.
- **`LogStream` column shows `allowed`** — expected for log-stream-level actions (`CreateLogStream`, `PutLogEvents`, `GetLogEvents`)

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
