variable "lambda_name" {
  type = string
  description = "The name of the Lambda function which we'll deploy"
  default = "SnykCloudAccountMonitorFunction"
}

variable "snyk_api_token" {
  type = string
  description = "The API token to use when connecting to Snyk"
}

variable "account_monitor_config" {
  type = string
  description = "The JSON string which represents the account monitor configuration rules"
}