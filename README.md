# eks-terraform-self-managed-worker
AWS EKS  with Self Managed worker nodes Implementation using Terraform

Terraform will perform the following actions:

  # module.alb.aws_alb.eks-alb will be created
  + resource "aws_alb" "eks-alb" {
      + arn                        = (known after apply)
      + arn_suffix                 = (known after apply)
      + dns_name                   = (known after apply)
      + drop_invalid_header_fields = false
      + enable_deletion_protection = false
      + enable_http2               = true
      + id                         = (known after apply)
      + idle_timeout               = 60
      + internal                   = (known after apply)
      + ip_address_type            = "ipv4"
      + load_balancer_type         = "application"
      + name                       = "eks-alb"
      + security_groups            = (known after apply)
      + subnets                    = (known after apply)
      + tags                       = {
          + "Name"                          = "eks-alb"
          + "kubernetes.io/cluster/example" = "owned"
        }
      + vpc_id                     = (known after apply)
      + zone_id                    = (known after apply)

      + subnet_mapping {
          + allocation_id = (known after apply)
          + subnet_id     = (known after apply)
        }
    }

  # module.alb.aws_alb_listener.eks-alb will be created
  + resource "aws_alb_listener" "eks-alb" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 80
      + protocol          = "HTTP"
      + ssl_policy        = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # module.alb.aws_security_group.eks-alb will be created
  + resource "aws_security_group" "eks-alb" {
      + arn                    = (known after apply)
      + description            = "Security group allowing public traffic for the eks load balancer."
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = "eks-alb-public"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name"                          = "terraform-eks-alb"
          + "kubernetes.io/cluster/example" = "owned"
        }
      + vpc_id                 = (known after apply)
    }

  # module.alb.aws_security_group_rule.eks-alb-public-http will be created
  + resource "aws_security_group_rule" "eks-alb-public-http" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Allow eks load balancer to communicate with public traffic."
      + from_port                = 80
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 80
      + type                     = "ingress"
    }

  # module.eks.data.aws_eks_cluster_auth.tf_eks will be read during apply
  # (config refers to values not yet known)
 <= data "aws_eks_cluster_auth" "tf_eks"  {
      + id    = (known after apply)
      + name  = "example-cluster"
      + token = (sensitive value)
    }

  # module.eks.aws_autoscaling_group.tf_eks will be created
  + resource "aws_autoscaling_group" "tf_eks" {
      + arn                       = (known after apply)
      + availability_zones        = (known after apply)
      + default_cooldown          = (known after apply)
      + desired_capacity          = 2
      + force_delete              = false
      + health_check_grace_period = 300
      + health_check_type         = (known after apply)
      + id                        = (known after apply)
      + launch_configuration      = (known after apply)
      + load_balancers            = (known after apply)
      + max_size                  = 3
      + metrics_granularity       = "1Minute"
      + min_size                  = 1
      + name                      = "terraform-tf-eks"
      + protect_from_scale_in     = false
      + service_linked_role_arn   = (known after apply)
      + target_group_arns         = (known after apply)
      + vpc_zone_identifier       = (known after apply)
      + wait_for_capacity_timeout = "10m"

      + tag {
          + key                 = "Name"
          + propagate_at_launch = true
          + value               = "terraform-tf-eks"
        }
      + tag {
          + key                 = "kubernetes.io/cluster/example-cluster"
          + propagate_at_launch = true
          + value               = "owned"
        }
    }

  # module.eks.aws_eks_cluster.tf_eks will be created
  + resource "aws_eks_cluster" "tf_eks" {
      + arn                   = (known after apply)
      + certificate_authority = (known after apply)
      + created_at            = (known after apply)
      + endpoint              = (known after apply)
      + id                    = (known after apply)
      + identity              = (known after apply)
      + name                  = "example-cluster"
      + platform_version      = (known after apply)
      + role_arn              = (known after apply)
      + status                = (known after apply)
      + version               = "1.17"

      + vpc_config {
          + cluster_security_group_id = (known after apply)
          + endpoint_private_access   = false
          + endpoint_public_access    = true
          + public_access_cidrs       = (known after apply)
          + security_group_ids        = (known after apply)
          + subnet_ids                = (known after apply)
          + vpc_id                    = (known after apply)
        }
    }

  # module.eks.aws_iam_instance_profile.node will be created
  + resource "aws_iam_instance_profile" "node" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "terraform-eks-node"
      + path        = "/"
      + role        = "terraform-eks-tf-eks-node"
      + roles       = (known after apply)
      + unique_id   = (known after apply)
    }

  # module.eks.aws_iam_role.tf-eks-master will be created
  + resource "aws_iam_role" "tf-eks-master" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "eks.amazonaws.com"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + max_session_duration  = 3600
      + name                  = "terraform-eks-cluster"
      + path                  = "/"
      + unique_id             = (known after apply)
    }

  # module.eks.aws_iam_role.tf-eks-node will be created
  + resource "aws_iam_role" "tf-eks-node" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + max_session_duration  = 3600
      + name                  = "terraform-eks-tf-eks-node"
      + path                  = "/"
      + unique_id             = (known after apply)
    }

  # module.eks.aws_iam_role_policy_attachment.tf-cluster-AmazonEKSClusterPolicy will be created
  + resource "aws_iam_role_policy_attachment" "tf-cluster-AmazonEKSClusterPolicy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
      + role       = "terraform-eks-cluster"
    }

  # module.eks.aws_iam_role_policy_attachment.tf-cluster-AmazonEKSServicePolicy will be created
  + resource "aws_iam_role_policy_attachment" "tf-cluster-AmazonEKSServicePolicy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
      + role       = "terraform-eks-cluster"
    }

  # module.eks.aws_iam_role_policy_attachment.tf-eks-node-AmazonEC2ContainerRegistryReadOnly will be created
  + resource "aws_iam_role_policy_attachment" "tf-eks-node-AmazonEC2ContainerRegistryReadOnly" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
      + role       = "terraform-eks-tf-eks-node"
    }

  # module.eks.aws_iam_role_policy_attachment.tf-eks-node-AmazonEKSWorkerNodePolicy will be created
  + resource "aws_iam_role_policy_attachment" "tf-eks-node-AmazonEKSWorkerNodePolicy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
      + role       = "terraform-eks-tf-eks-node"
    }

  # module.eks.aws_iam_role_policy_attachment.tf-eks-node-AmazonEKS_CNI_Policy will be created
  + resource "aws_iam_role_policy_attachment" "tf-eks-node-AmazonEKS_CNI_Policy" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
      + role       = "terraform-eks-tf-eks-node"
    }

  # module.eks.aws_launch_configuration.tf_eks will be created
  + resource "aws_launch_configuration" "tf_eks" {
      + arn                         = (known after apply)
      + associate_public_ip_address = true
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = "terraform-eks-node"
      + id                          = (known after apply)
      + image_id                    = "ami-04125ecea1c9b3b27"
      + instance_type               = "m4.large"
      + key_name                    = "testing-key-ue"
      + name                        = (known after apply)
      + name_prefix                 = "terraform-eks"
      + security_groups             = (known after apply)
      + user_data_base64            = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + no_device             = (known after apply)
          + snapshot_id           = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # module.eks.aws_lb_target_group.tf_eks will be created
  + resource "aws_lb_target_group" "tf_eks" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + deregistration_delay               = 300
      + id                                 = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + name                               = "terraform-eks-nodes"
      + port                               = 31742
      + protocol                           = "HTTP"
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + target_type                        = "instance"
      + vpc_id                             = (known after apply)

      + health_check {
          + enabled             = (known after apply)
          + healthy_threshold   = (known after apply)
          + interval            = (known after apply)
          + matcher             = (known after apply)
          + path                = (known after apply)
          + port                = (known after apply)
          + protocol            = (known after apply)
          + timeout             = (known after apply)
          + unhealthy_threshold = (known after apply)
        }

      + stickiness {
          + cookie_duration = (known after apply)
          + enabled         = (known after apply)
          + type            = (known after apply)
        }
    }

  # module.eks.aws_security_group.tf-eks-master will be created
  + resource "aws_security_group" "tf-eks-master" {
      + arn                    = (known after apply)
      + description            = "Cluster communication with worker nodes"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = "terraform-eks-cluster"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "terraform-eks"
        }
      + vpc_id                 = (known after apply)
    }

  # module.eks.aws_security_group.tf-eks-node will be created
  + resource "aws_security_group" "tf-eks-node" {
      + arn                    = (known after apply)
      + description            = "Security group for all nodes in the cluster"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = "terraform-eks-node"
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "terraform-eks"
        }
      + vpc_id                 = (known after apply)
    }

  # module.eks.aws_security_group_rule.tf-eks-cluster-ingress-node-https will be created
  + resource "aws_security_group_rule" "tf-eks-cluster-ingress-node-https" {
      + description              = "Allow pods to communicate with the cluster API Server"
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.tf-eks-cluster-ingress-workstation-https will be created
  + resource "aws_security_group_rule" "tf-eks-cluster-ingress-workstation-https" {
      + cidr_blocks              = [
          + "123.208.19.128/32",
        ]
      + description              = "Allow workstation to communicate with the cluster API Server"
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.tf-eks-node-ingress-cluster will be created
  + resource "aws_security_group_rule" "tf-eks-node-ingress-cluster" {
      + description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
      + from_port                = 1025
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 65535
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.tf-eks-node-ingress-master will be created
  + resource "aws_security_group_rule" "tf-eks-node-ingress-master" {
      + description              = "Allow cluster control to receive communication from the worker Kubelets"
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.eks.aws_security_group_rule.tf-eks-node-ingress-self will be created
  + resource "aws_security_group_rule" "tf-eks-node-ingress-self" {
      + description              = "Allow node to communicate with each other"
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 65535
      + type                     = "ingress"
    }

  # module.eks.kubernetes_config_map.aws_auth will be created
  + resource "kubernetes_config_map" "aws_auth" {
      + data = (known after apply)
      + id   = (known after apply)

      + metadata {
          + generation       = (known after apply)
          + name             = "aws-auth"
          + namespace        = "kube-system"
          + resource_version = (known after apply)
          + self_link        = (known after apply)
          + uid              = (known after apply)
        }
    }

  # module.network.aws_eip.nat_gateway[0] will be created
  + resource "aws_eip" "nat_gateway" {
      + allocation_id     = (known after apply)
      + association_id    = (known after apply)
      + customer_owned_ip = (known after apply)
      + domain            = (known after apply)
      + id                = (known after apply)
      + instance          = (known after apply)
      + network_interface = (known after apply)
      + private_dns       = (known after apply)
      + private_ip        = (known after apply)
      + public_dns        = (known after apply)
      + public_ip         = (known after apply)
      + public_ipv4_pool  = (known after apply)
      + vpc               = true
    }

  # module.network.aws_eip.nat_gateway[1] will be created
  + resource "aws_eip" "nat_gateway" {
      + allocation_id     = (known after apply)
      + association_id    = (known after apply)
      + customer_owned_ip = (known after apply)
      + domain            = (known after apply)
      + id                = (known after apply)
      + instance          = (known after apply)
      + network_interface = (known after apply)
      + private_dns       = (known after apply)
      + private_ip        = (known after apply)
      + public_dns        = (known after apply)
      + public_ip         = (known after apply)
      + public_ipv4_pool  = (known after apply)
      + vpc               = true
    }

  # module.network.aws_internet_gateway.example will be created
  + resource "aws_internet_gateway" "example" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "internet_gateway"
        }
      + vpc_id   = (known after apply)
    }

  # module.network.aws_nat_gateway.example[0] will be created
  + resource "aws_nat_gateway" "example" {
      + allocation_id        = (known after apply)
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "nat_gateway"
        }
    }

  # module.network.aws_nat_gateway.example[1] will be created
  + resource "aws_nat_gateway" "example" {
      + allocation_id        = (known after apply)
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "nat_gateway"
        }
    }

  # module.network.aws_route_table.private[0] will be created
  + resource "aws_route_table" "private" {
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + cidr_block                = "0.0.0.0/0"
              + egress_only_gateway_id    = ""
              + gateway_id                = ""
              + instance_id               = ""
              + ipv6_cidr_block           = ""
              + nat_gateway_id            = (known after apply)
              + network_interface_id      = ""
              + transit_gateway_id        = ""
              + vpc_peering_connection_id = ""
            },
        ]
      + tags             = {
          + "Name" = "example_private"
        }
      + vpc_id           = (known after apply)
    }

  # module.network.aws_route_table.private[1] will be created
  + resource "aws_route_table" "private" {
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + cidr_block                = "0.0.0.0/0"
              + egress_only_gateway_id    = ""
              + gateway_id                = ""
              + instance_id               = ""
              + ipv6_cidr_block           = ""
              + nat_gateway_id            = (known after apply)
              + network_interface_id      = ""
              + transit_gateway_id        = ""
              + vpc_peering_connection_id = ""
            },
        ]
      + tags             = {
          + "Name" = "example_private"
        }
      + vpc_id           = (known after apply)
    }

  # module.network.aws_route_table.public will be created
  + resource "aws_route_table" "public" {
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + cidr_block                = "0.0.0.0/0"
              + egress_only_gateway_id    = ""
              + gateway_id                = (known after apply)
              + instance_id               = ""
              + ipv6_cidr_block           = ""
              + nat_gateway_id            = ""
              + network_interface_id      = ""
              + transit_gateway_id        = ""
              + vpc_peering_connection_id = ""
            },
        ]
      + tags             = {
          + "Name" = "example_public"
        }
      + vpc_id           = (known after apply)
    }

  # module.network.aws_route_table_association.private[0] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.network.aws_route_table_association.private[1] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.network.aws_route_table_association.public[0] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.network.aws_route_table_association.public[1] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.network.aws_subnet.private[0] will be created
  + resource "aws_subnet" "private" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "us-east-1a"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.20.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name"                          = "example_application"
          + "kubernetes.io/cluster/example" = "shared"
        }
      + vpc_id                          = (known after apply)
    }

  # module.network.aws_subnet.private[1] will be created
  + resource "aws_subnet" "private" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "us-east-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.21.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name"                          = "example_application"
          + "kubernetes.io/cluster/example" = "shared"
        }
      + vpc_id                          = (known after apply)
    }

  # module.network.aws_subnet.public[0] will be created
  + resource "aws_subnet" "public" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "us-east-1a"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.10.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name" = "example_gateway"
        }
      + vpc_id                          = (known after apply)
    }

  # module.network.aws_subnet.public[1] will be created
  + resource "aws_subnet" "public" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "us-east-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.0.11.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block                 = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags                            = {
          + "Name" = "example_gateway"
        }
      + vpc_id                          = (known after apply)
    }

  # module.network.aws_vpc.example will be created
  + resource "aws_vpc" "example" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = false
      + cidr_block                       = "10.0.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = (known after apply)
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name"                          = "terraform-eks"
          + "kubernetes.io/cluster/example" = "shared"
        }
    }

Plan: 41 to add, 0 to change, 0 to destroy.


