# Simple check that cost estimate is above threshold.
package terraform

import input.tfrun as tfrun

deny[reason] {
    cost = tfrun.cost_estimate.proposed_monthly_cost
    cost > 100
    reason := sprintf("Plan is too expensive: $%.2f, while up to $100 is allowed", [cost])
}