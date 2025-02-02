variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = "list"
  description = "List containing the IDs of all created gateway subnets."
}

variable "node_sg_id" {
  type = string
  description = "ID of the Security Group used by the Kubernetes worker nodes."
}

variable "lb_target_group_arn" {
  type = string
  description = "ARN of the Target Group pointing at the Kubernetes nodes."
}
