resource "aws_route_table" "private" {
  count = "${var.subnet_count}"
  vpc_id = "${aws_vpc.example.id}"
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = "${aws_nat_gateway.example.*.id[count.index]}"
  }
  tags = {
    Name = "example_private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = "${aws_vpc.example.id}"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.example.id}"
  }
  tags = {
    Name = "example_public"
  }
}

resource "aws_route_table_association" "private" {
  count = "${var.subnet_count}"

  subnet_id      = "${aws_subnet.private.*.id[count.index]}"
  route_table_id = "${aws_route_table.private.*.id[count.index]}"
}


resource "aws_route_table_association" "public" {
  count = "${var.subnet_count}"

  subnet_id      = "${aws_subnet.public.*.id[count.index]}"
  route_table_id = "${aws_route_table.public.id}"
}
