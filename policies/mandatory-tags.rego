package terraform

import input.tfplan as tfplan

required_tags = ["t_environment", "t_AppID", "t_dcl"]

ec2_instances[r] {
    r := tfplan.resource_changes[_]
    r.type == "aws_instance"
    r.change.actions[_] == "create"
    r.change.actions[_] == "update"
}

deny[msg] {
    ec2_instances[r]
    missing_tags := [tag_key | tag_key := required_tags; not r.change.after.tags[tag_key]]
    count(missing_tags) > 0
    msg := sprintf("EC2 instance '%v' is missing required tags: %v", [r.address, missing_tags])
}
