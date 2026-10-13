# Terraform / OpenTofu external data source bridge
# Usage:
#   data "external" "kazeshini" {
#     program = ["/usr/local/bin/kazeshini", "facts", "--json"]
#   }
#
# Returns string-valued attributes matching Terraform's external program contract.

data "external" "kazeshini" {
  program = ["sh", "-c", "kazeshini facts --json | jq '{host_id: .host_id, verdict_status: .verdict_status, chaos_index: (.chaos_index|tostring), coverage_percent: (.coverage_percent|tostring)}'"]
}

output "verdict" {
  value = data.external.kazeshini.result.verdict_status
}

output "chaos_index" {
  value = data.external.kazeshini.result.chaos_index
}

