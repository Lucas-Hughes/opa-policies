version = "v1"

policy "cost-per-month" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

// policy "instance-size-in-lower" {
//   enabled           = true
//   enforcement_level = "hard-mandatory"
// }

policy "mandatory-tags" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "no-administrator-role" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "no-open-cidr" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "enforce-s3-encryption" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "enforce-s3-private" {
  enabled           = true
  enforcement_level = "advisory"
}

policy "prevent-workspace-deletion" {
  enabled           = true
  enforcement_level = "advisory"
}
