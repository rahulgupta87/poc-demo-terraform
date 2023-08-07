variable "env_type"  {
	type        = string
	description = "Environment dev/qa/prod"
}

variable "domain" {
  type = string
}

variable "custom_domain" {
  type    = string
}

variable "subnet_ids"  {
  type    = list(string)
}

variable "security_group_ids" {
  type = list(string)
}

variable"thirdparty_client_id" {
  type = string
}

variable "thirdparty_access_token" {
  type = string
}

variable "tags" {
  description = "Custom tags which can be passed on to the AWS resources. They should be key value pairs having distinct keys"
  type        = map(string)
  default     = {}
}

variable "dynamo_backup_tags" {
  description = "Custom tags for AWS Dynamo Backup."
  type        = map(string)
}
