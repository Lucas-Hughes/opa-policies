package terraform

import input.tfplan as tfplan

disallowed_policies = ["AdministratorAccess", "PowerUserAccess"]

iam_roles[r] {
  r := tfplan.resource_changes[_]
  r.type == "aws_iam_role"
}

deny {
  iam_roles[r]
  disallowed_policies[_] == r.change.after.assume_role_policy[0].statement[_].action[0]
}
