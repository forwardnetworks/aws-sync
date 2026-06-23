variable "stack_set_name" {
  description = "CloudFormation StackSet name."
  type        = string
  default     = "forward-collection-role"
}

variable "role_name" {
  description = "IAM role name to create in each target AWS account. Must match awssync --role-name."
  type        = string
  default     = "ForwardRole"
}

variable "trusted_principal_arns" {
  description = "AWS principal ARNs allowed to assume the Forward collection role."
  type        = list(string)

  validation {
    condition     = length(var.trusted_principal_arns) > 0
    error_message = "trusted_principal_arns must contain at least one AWS principal ARN."
  }
}

variable "external_id" {
  description = "Optional external ID required by the collection role trust policy."
  type        = string
  default     = null
}

variable "target_ou_ids" {
  description = "AWS Organizations root or OU IDs to receive the StackSet. Use the root ID to target the whole org except the management account."
  type        = list(string)

  validation {
    condition     = length(var.target_ou_ids) > 0
    error_message = "target_ou_ids must contain at least one root or OU ID."
  }
}

variable "target_account_ids" {
  description = "Optional account filter for the targeted OUs. Leave empty to target all accounts in target_ou_ids."
  type        = list(string)
  default     = []
}

variable "account_filter_type" {
  description = "StackSet account filter type when target_account_ids is non-empty."
  type        = string
  default     = "INTERSECTION"

  validation {
    condition     = contains(["INTERSECTION", "DIFFERENCE", "UNION"], var.account_filter_type)
    error_message = "account_filter_type must be INTERSECTION, DIFFERENCE, or UNION."
  }
}

variable "deployment_regions" {
  description = "Regions where CloudFormation creates StackSet instances. IAM is global, but StackSets still require a region."
  type        = list(string)
  default     = ["us-east-1"]
}

variable "managed_policy_arns" {
  description = "Managed policies attached to the collection role. Replace ReadOnlyAccess with a Forward-approved least-privilege policy when available."
  type        = list(string)
  default     = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
}

variable "inline_policy_name" {
  description = "Name for optional inline policy."
  type        = string
  default     = "ForwardCollectionPolicy"
}

variable "inline_policy_json" {
  description = "Optional inline IAM policy JSON for the collection role."
  type        = string
  default     = null
}

variable "retain_stacks_on_account_removal" {
  description = "Retain stacks when accounts leave targeted OUs."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags added to the collection role."
  type        = map(string)
  default     = {}
}
