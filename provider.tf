provider "aws" {
 region  = var.aws_region
 version = "~> 2.70.0"
# access_key = "${var.aws_access_key}"
# secret_key = "${var.aws_secret_key}"
}

#provider "kubernetes" {
#  host                      = "${aws_eks_cluster.tf_eks.endpoint}"
#  cluster_ca_certificate    = "${base64decode(aws_eks_cluster.tf_eks.certificate_authority.0.data)}"
#  token                      = "${data.aws_eks_cluster_auth.tf_eks.token}"
#  load_config_file          = false
#  version = "~> 1.5"
#}
