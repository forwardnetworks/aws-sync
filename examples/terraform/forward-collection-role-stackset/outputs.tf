output "stack_set_name" {
  description = "CloudFormation StackSet name."
  value       = aws_cloudformation_stack_set.this.name
}

output "role_name" {
  description = "Forward collection role name to pass to awssync --role-name."
  value       = var.role_name
}

output "target_ou_ids" {
  description = "Targeted AWS Organizations root or OU IDs."
  value       = var.target_ou_ids
}
