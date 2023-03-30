package terraform

import input.tfplan as tfplan

allowed_sse_algorithms = ["aws:kms", "AES256"]

s3_buckets[r] {
    r := tfplan.resource_changes[_]
    r.type == "aws_s3_bucket"
}

array_contains(arr, elem) {
  arr[_] = elem
}

# Rule to require server-side encryption
deny[reason] {
    r := s3_buckets[_]
    count(r.change.after.server_side_encryption_configuration) == 0
    reason := sprintf(
        "%s: requires server-side encryption with expected sse_algorithm to be one of %v",
        [r.address, allowed_sse_algorithms]
    )
}