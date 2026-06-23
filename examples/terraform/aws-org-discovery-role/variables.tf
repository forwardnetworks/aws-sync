variable "role_name" {
  description = "IAM role name for awssync AWS Organizations discovery."
  type        = string
  default     = "awssync-org-discovery"
}

variable "trusted_principal_arns" {
  description = "AWS principal ARNs allowed to assume the discovery role."
  type        = list(string)

  validation {
    condition     = length(var.trusted_principal_arns) > 0
    error_message = "trusted_principal_arns must contain at least one AWS principal ARN."
  }
}

variable "external_id" {
  description = "Optional external ID required by the role trust policy."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags added to created IAM resources."
  type        = map(string)
  default     = {}
}
