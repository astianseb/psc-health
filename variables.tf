variable "parent" {
  type = object({
    parent_type = string
    parent_id   = string
  })
  default = {
    parent_id   = null
    parent_type = null
  }
}

variable "folder_id" {
  default = null
}

variable "region_1" {}

variable "region_2" {}

variable "billing_account" {}

variable "producer_project_name" {
  default = "producer"
}

variable "consumer_project_name" {
  default = "consumer"
}



