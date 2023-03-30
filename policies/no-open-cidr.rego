package terraform 

import input.tfplan as tfplan

# Add CIDRS that should be disallowed
invalid_cidrs = [
    "0.0.0.0/0"
]

allowed_ports = [
    "80","443","8443"
]

array_contains(arr, elem) {
  arr[_] = elem
}

# Checks security groups embdedded ingress rules
deny[reason] {
  r := tfplan.resource_changes[_]
  r.type == "aws_security_group"
  in := r.change.after.ingress[_]
  valid := allowed_ports[_]
  invalid := invalid_cidrs[_]
  array_contains(in.cidr_blocks,invalid)
  not array_contains(valid, r.change.after.from_port, r.change.after.to_port)
  reason := sprintf(
              "%-40s :: security group invalid ingress CIDR %s",
              [r.address,invalid]
            )
}

# Checks security groups rules
deny[reason] {
  r := tfplan.resource_changes[_]
  r.type == "aws_security_group_rule"
  valid := allowed_ports[_]
  invalid := invalid_cidrs[_]
  array_contains(r.change.after.cidr_blocks,invalid)
  not array_contains(valid, r.change.after.from_port, r.change.after.to_port)
  reason := sprintf(
              "%-40s :: security group rule invalid  CIDR %s",
              [r.address,invalid]
            )
}