output "role_arn" {
  description = "IAM role ARN for awssync AWS Organizations discovery."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "IAM role name for awssync AWS Organizations discovery."
  value       = aws_iam_role.this.name
}
