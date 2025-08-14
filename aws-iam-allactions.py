import boto3
import botocore
import json

# Configurable threshold for what counts as "many" actions ACTION_COUNT_THRESHOLD = 20
ACTION_COUNT_THRESHOLD = 20

def is_action_wildcard(statement):
     """Returns True if the statement allows Action: '*' with Allow and no restrictions."""
     if statement.get("Effect") != "Allow":
         return False

     actions = statement.get("Action", [])
     actions = [actions] if isinstance(actions, str) else actions

     if "*" not in actions:
         return False

     resources = statement.get("Resource", "*")
     resources = [resources] if isinstance(resources, str) else resources

     condition = statement.get("Condition", {})

     return ("*" in resources or any(":*" in r for r in resources)) and not condition

def is_many_actions(statement):
     """Returns True if the statement allows many actions, over a defined threshold."""
     if statement.get("Effect") != "Allow":
         return False

     actions = statement.get("Action", [])
     actions = [actions] if isinstance(actions, str) else actions

     # Filter out duplicates
     unique_actions = list(set(actions))

     # Ignore if it's just "*" — already handled
     if "*" in unique_actions:
         return False

     return len(unique_actions) >= ACTION_COUNT_THRESHOLD

def main():
     iam = boto3.client("iam")
     paginator = iam.get_paginator("list_policies")

     findings_wildcard = []
     findings_many_actions = []
     permission_issues = []

     print("🔍 Scanning customer-managed IAM policies for overly broad permissions...\n")

     try:
         for page in paginator.paginate(Scope="Local"):  # Only customer-managed policies
             for policy in page.get("Policies", []):
                 policy_name = policy.get("PolicyName")
                 policy_arn = policy.get("Arn")

                 try:
                     policy_data = iam.get_policy(PolicyArn=policy_arn)["Policy"]
                     version_id = policy_data["DefaultVersionId"]

                     try:
                         version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                         document = version["PolicyVersion"]["Document"]
                         statements = document.get("Statement", [])
                         if isinstance(statements, dict):
                             statements = [statements]

                         for stmt in statements:
                             if is_action_wildcard(stmt):
                                 findings_wildcard.append({
                                     "PolicyName": policy_name,
                                     "PolicyArn": policy_arn,
                                     "Statement": stmt
                                 })
                             elif is_many_actions(stmt):
                                 findings_many_actions.append({
                                     "PolicyName": policy_name,
                                     "PolicyArn": policy_arn,
                                     "Statement": stmt,
                                     "ActionCount": len(set(stmt["Action"])) if isinstance(stmt["Action"], list) else 1
                                 })

                     except botocore.exceptions.ClientError as e:
                         permission_issues.append(f"iam:GetPolicyVersion on {policy_name} — {e.response['Error']['Code']}")

                 except botocore.exceptions.ClientError as e:
                     permission_issues.append(f"iam:GetPolicy on {policy_name} — {e.response['Error']['Code']}")

     except botocore.exceptions.ClientError as e:
         print(f"❌ Error listing policies: {e.response['Error']['Message']}")
         return

     # Print wildcard findings
     if findings_wildcard:
         print(f"\n❗ Found {len(findings_wildcard)} policies with unrestricted 'Allow: *':\n")
         for f in findings_wildcard:
             print(f"- Policy: {f['PolicyName']}")
             print(f"  ARN: {f['PolicyArn']}")
             print(f"  Statement:\n{json.dumps(f['Statement'], indent=2)}\n")
     else:
         print("✅ No policies with 'Action: *' found.\n")

     # Print broad-action findings
     if findings_many_actions:
         print(f"\n⚠️ Found {len(findings_many_actions)} policies with many allowed actions (>{ACTION_COUNT_THRESHOLD}):\n")
         for f in findings_many_actions:
             print(f"- Policy: {f['PolicyName']} ({f['ActionCount']} actions)")
             print(f"  ARN: {f['PolicyArn']}")
             print(f"  Statement:\n{json.dumps(f['Statement'], indent=2)}\n")
     else:
         print("✅ No policies found with excessive numbers of actions.\n")

     # Permission issues
     if permission_issues:
         print("\n⚠️ Permission issues encountered during scanning:")
         for issue in sorted(set(permission_issues)):
             print(f"- {issue}")

     print("\n✅ Scan complete.")

if __name__ == "__main__":
     main()
