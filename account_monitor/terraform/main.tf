# Store the secret for the Snyk Token
resource "aws_secretsmanager_secret" "snyk_token_secret" {
  name = "snyk-tf/account_monitor/token"
  description = "The Snyk API token"
}
resource "aws_secretsmanager_secret_version" "snyk_token_secret_version" {
  secret_id     = aws_secretsmanager_secret.snyk_token_secret.id
  secret_string = jsonencode({"token"=var.snyk_api_token})
}

# Mapping rules are stored as a JSON string in parameter store
resource "aws_ssm_parameter" "account_monitor_config" {
  name  = "/snyk/account_monitor/config"
  type  = "String"
  value = var.account_monitor_config
}

# Create a number of rules to trigger our lambda function
resource "aws_cloudwatch_event_rule" "account_creation_rule" {
  for_each = {
    "ControlTower": "CreateManagedAccount",
    "Orgs": "CreateAccountResult"
  }
  name        = "SnykCloud${each.key}AccountCreated"
  description = "CloudWatch Rule to Trigger Snyk AWS Account Monitor Lambda"

  event_pattern = <<EOF
{
  "eventName": [
    "${each.value}"
  ]
}
EOF
}

# Ensure all of our rules target our Lambda function
resource "aws_cloudwatch_event_target" "account_creation_target" {
  for_each = aws_cloudwatch_event_rule.account_creation_rule
  rule = each.value.name
  arn = aws_lambda_function.snyk_cloud_monitor_function.arn
}

# Ensure EventBridge can invoke our function
resource "aws_lambda_permission" "account_creation_permissions" {
  for_each = aws_cloudwatch_event_rule.account_creation_rule
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.snyk_cloud_monitor_function.arn
  principal = "events.amazonaws.com"
  source_arn = each.value.arn
}


# IAM roles / policies which our Lambda assumes
resource "aws_iam_role" "lambda_role" {
  name = "SnykCloudAWSMonitor"
  managed_policy_arns = [aws_iam_policy.lambda_policy.arn]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}
resource "aws_iam_policy" "lambda_policy" {
  name        = "AWSAccountMonitorPolicy"
  path        = "/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Decrypt",
        ]
        Effect   = "Allow"
        Resource = "*",
        Condition = {
          StringEquals: {
            "kms:RequestAlias"="aws/secretsmanager"
          }
        }
      },
      {
        Action = [
          "sts:AssumeRole",
        ]
        Effect   = "Allow"
        Resource = [
          "arn:aws:iam::*:role/OrganizationAccountAccessRole",
          "arn:aws:iam::*:role/AWSControlTowerExecution"
        ]
      },
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "ssm:GetParameter"
        ]
        Effect   = "Allow"
        Resource = [
          aws_secretsmanager_secret.snyk_token_secret.arn,
          aws_ssm_parameter.account_monitor_config.arn
        ]
      },
      {
        Action = [
          "organizations:DescribeAccount"
        ]
        Effect   = "Allow"
        Resource = [
          "*"
        ]
      }
    ]
  })
}

# Deploy our Lambda function
resource "aws_lambda_function" "snyk_cloud_monitor_function" {
    function_name = var.lambda_name
    description = "Snyk Cloud AWS Account Monitor Function"
    handler = "main.lambda_handler"
    s3_bucket = "aws-account-monitor"
    s3_key = "lambda-account-monitor-package-v0.3.0.zip"
    memory_size = 128
    role = "${aws_iam_role.lambda_role.arn}"
    runtime = "python3.9"
    timeout = 600
    environment {
        variables = {
            SSM_CONFIG_NAME = aws_ssm_parameter.account_monitor_config.name
            SNYK_TOKEN_SECRET = aws_secretsmanager_secret.snyk_token_secret.arn
        }
    }
}