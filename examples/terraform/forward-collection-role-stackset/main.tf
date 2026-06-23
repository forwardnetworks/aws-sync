locals {
  assume_role_condition = var.external_id == null ? {} : {
    Condition = {
      StringEquals = {
        "sts:ExternalId" = var.external_id
      }
    }
  }

  assume_role_policy = {
    Version = "2012-10-17"
    Statement = [
      merge(
        {
          Effect = "Allow"
          Principal = {
            AWS = var.trusted_principal_arns
          }
          Action = "sts:AssumeRole"
        },
        local.assume_role_condition
      )
    ]
  }

  inline_policy = var.inline_policy_json == null ? {} : {
    Policies = [
      {
        PolicyName     = var.inline_policy_name
        PolicyDocument = jsondecode(var.inline_policy_json)
      }
    ]
  }

  role_tags = [
    for key, value in var.tags : {
      Key   = key
      Value = value
    }
  ]

  role_properties = merge(
    {
      RoleName                 = var.role_name
      AssumeRolePolicyDocument = local.assume_role_policy
      ManagedPolicyArns        = var.managed_policy_arns
      Tags                     = local.role_tags
    },
    local.inline_policy
  )

  template = {
    AWSTemplateFormatVersion = "2010-09-09"
    Description              = "Forward collection IAM role deployed by StackSets."
    Resources = {
      ForwardCollectionRole = {
        Type       = "AWS::IAM::Role"
        Properties = local.role_properties
      }
    }
    Outputs = {
      RoleArn = {
        Description = "Forward collection role ARN."
        Value = {
          "Fn::GetAtt" = ["ForwardCollectionRole", "Arn"]
        }
      }
    }
  }
}

resource "aws_cloudformation_stack_set" "this" {
  name             = var.stack_set_name
  permission_model = "SERVICE_MANAGED"
  capabilities     = ["CAPABILITY_NAMED_IAM"]
  template_body    = jsonencode(local.template)

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = var.retain_stacks_on_account_removal
  }

  managed_execution {
    active = true
  }

  operation_preferences {
    failure_tolerance_percentage = 10
    max_concurrent_percentage    = 25
    region_concurrency_type      = "PARALLEL"
  }
}

resource "aws_cloudformation_stack_set_instance" "this" {
  for_each       = toset(var.deployment_regions)
  stack_set_name = aws_cloudformation_stack_set.this.name
  region         = each.value

  deployment_targets {
    organizational_unit_ids = var.target_ou_ids
    accounts                = length(var.target_account_ids) == 0 ? null : var.target_account_ids
    account_filter_type     = length(var.target_account_ids) == 0 ? "NONE" : var.account_filter_type
  }
}
