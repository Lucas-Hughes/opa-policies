package main

import data.terraform

# Define the allowed instance class
allowed_instance_class = "t"

# Define the main rule to restrict the instances
default restrict_instance = false {
    # Loop over all resources in the plan
    some resource_type
    terraform.resource_changes[resource_type] as changes
    some change_index
    # Check if the change is for an EC2 instance
    resource_type == "aws_instance"
    # Check if the instance is in the DEMO or DEV environment
    environment := changes[change_index].change.after.tags["t_environment"]
    environment == "DEMO" or environment == "DEV"
    # Check if the instance type is outside the allowed instance class
    instance_type := changes[change_index].change.after.instance_type
    not starts_with(instance_type, allowed_instance_class)
}

# Define a rule to allow the change if it doesn't violate the main rule
allow_instance_change {
    not restrict_instance
}
