module "network" {
  source = "./modules/network"
  aws_region       = "${var.aws_region}"
  subnet_count     = "${var.subnet_count}"
}

module "eks" {
  source = "./modules/eks"
  aws_region              = "${var.aws_region}"
  keypair-name            = "${var.keypair-name}"
  vpc_id                  = "${module.network.vpc_id}"
  private_subnet_ids = [
      "${module.network.private_subnet_ids}",
   ]
  cluster_version         = "${var.cluster_version}"

}

module "alb" {
  source = "./modules/alb"
  vpc_id                  = "${module.network.vpc_id}"
  public_subnet_ids = [
      "${module.network.public_subnet_ids}",
   ]
  node_sg_id              = "${module.eks.node_sg_id}"
  lb_target_group_arn     = "${module.eks.target_group_arn}"
}

module "app" {
  source = "./modules/app"

}
