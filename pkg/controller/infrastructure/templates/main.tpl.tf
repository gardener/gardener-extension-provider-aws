provider "aws" {
  access_key = var.ACCESS_KEY_ID
  secret_key = var.SECRET_ACCESS_KEY
  region     = "{{ .aws.region }}"
  {{- if or .ignoreTags.keys .ignoreTags.keyPrefixes }}
  ignore_tags {
    {{- if .ignoreTags.keys }}
    keys         = [{{ joinQuotes .ignoreTags.keys }}]
    {{- end }}
    {{- if .ignoreTags.keyPrefixes }}
    key_prefixes = [{{ joinQuotes .ignoreTags.keyPrefixes }}]
    {{- end }}
  }
  {{- end }}
}

//=====================================================================
//= VPC, DHCP Options, Gateways, Subnets, Route Tables, Security Groups
//=====================================================================

{{ if .create.vpc -}}
resource "aws_vpc_dhcp_options" "vpc_dhcp_options" {
  domain_name         = "{{ .vpc.dhcpDomainName }}"
  domain_name_servers = ["AmazonProvidedDNS"]

{{ commonTags .clusterName | indent 2 }}
}

resource "aws_vpc" "vpc" {
  cidr_block           = "{{ .vpc.cidr }}"
  enable_dns_support   = true
  enable_dns_hostnames = true

{{ commonTags .clusterName | indent 2 }}
}

resource "aws_vpc_dhcp_options_association" "vpc_dhcp_options_association" {
  vpc_id          = aws_vpc.vpc.id
  dhcp_options_id = aws_vpc_dhcp_options.vpc_dhcp_options.id
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.vpc.id
}

resource "aws_internet_gateway" "igw" {
  vpc_id = {{ .vpc.id }}

{{ commonTags .clusterName | indent 2 }}
}
{{- end}}

{{ range $ep := .vpc.gatewayEndpoints }}
resource "aws_vpc_endpoint" "vpc_gwep_{{ $ep }}" {
  vpc_id       = {{ $.vpc.id }}
  service_name = "com.amazonaws.{{ $.aws.region }}.{{ $ep }}"

{{ commonTagsWithSuffix $.clusterName (print "gw-" $ep) | indent 2 }}
}
{{ end }}

resource "aws_route_table" "routetable_main" {
  vpc_id = {{ .vpc.id }}

  timeouts {
    create = "5m"
  }

{{ commonTags .clusterName | indent 2 }}
}

resource "aws_route" "public" {
  route_table_id         = aws_route_table.routetable_main.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = {{ .vpc.internetGatewayID }}

  timeouts {
    create = "5m"
  }
}

resource "aws_security_group" "nodes" {
  name        = "{{ .clusterName }}-nodes"
  description = "Security group for nodes"
  vpc_id      = {{ .vpc.id }}

  timeouts {
    create = "5m"
    delete = "5m"
  }

{{ commonTagsWithSuffix .clusterName "nodes" | indent 2 }}
}

resource "aws_security_group_rule" "nodes_self" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  self              = true
  security_group_id = aws_security_group.nodes.id
}

resource "aws_security_group_rule" "nodes_tcp_all" {
  type              = "ingress"
  from_port         = 30000
  to_port           = 32767
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.nodes.id
}

resource "aws_security_group_rule" "nodes_udp_all" {
  type              = "ingress"
  from_port         = 30000
  to_port           = 32767
  protocol          = "udp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.nodes.id
}

resource "aws_security_group_rule" "nodes_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.nodes.id
}

{{ range $index, $zone := .zones }}
resource "aws_subnet" "nodes_z{{ $index }}" {
  vpc_id            = {{ $.vpc.id }}
  cidr_block        = "{{ $zone.worker }}"
  availability_zone = "{{ $zone.name }}"

  timeouts {
    create = "5m"
    delete = "5m"
  }

{{ commonTagsWithSuffix $.clusterName (print "nodes-z" $index) | indent 2 }}
}

output "{{ $.outputKeys.subnetsNodesPrefix }}{{ $index }}" {
  value = aws_subnet.nodes_z{{ $index }}.id
}

resource "aws_subnet" "private_utility_z{{ $index }}" {
  vpc_id            = {{ $.vpc.id }}
  cidr_block        = "{{ $zone.internal }}"
  availability_zone = "{{ $zone.name }}"

  timeouts {
    create = "5m"
    delete = "5m"
  }

  tags = {
    Name = "{{ $.clusterName }}-private-utility-z{{ $index }}"
    "kubernetes.io/cluster/{{ $.clusterName }}"  = "1"
    "kubernetes.io/role/internal-elb" = "use"
  }
}

resource "aws_security_group_rule" "nodes_tcp_internal_z{{ $index }}" {
  type              = "ingress"
  from_port         = 30000
  to_port           = 32767
  protocol          = "tcp"
  cidr_blocks       = ["{{ $zone.internal }}"]
  security_group_id = aws_security_group.nodes.id
}

resource "aws_security_group_rule" "nodes_udp_internal_z{{ $index }}" {
  type              = "ingress"
  from_port         = 30000
  to_port           = 32767
  protocol          = "udp"
  cidr_blocks       = ["{{ $zone.internal }}"]
  security_group_id = aws_security_group.nodes.id
}

resource "aws_subnet" "public_utility_z{{ $index }}" {
  vpc_id            = {{ $.vpc.id }}
  cidr_block        = "{{ $zone.public }}"
  availability_zone = "{{ $zone.name }}"

  timeouts {
    create = "5m"
    delete = "5m"
  }

  tags = {
    Name = "{{ $.clusterName }}-public-utility-z{{ $index }}"
    "kubernetes.io/cluster/{{ $.clusterName }}"  = "1"
    "kubernetes.io/role/elb" = "use"
  }
}

output "{{ $.outputKeys.subnetsPublicPrefix }}{{ $index }}" {
  value = aws_subnet.public_utility_z{{ $index }}.id
}

resource "aws_security_group_rule" "nodes_tcp_public_z{{ $index }}" {
  type              = "ingress"
  from_port         = 30000
  to_port           = 32767
  protocol          = "tcp"
  cidr_blocks       = ["{{ $zone.public }}"]
  security_group_id = aws_security_group.nodes.id
}

resource "aws_security_group_rule" "nodes_udp_public_z{{ $index }}" {
  type              = "ingress"
  from_port         = 30000
  to_port           = 32767
  protocol          = "udp"
  cidr_blocks       = ["{{ $zone.public }}"]
  security_group_id = aws_security_group.nodes.id
}

{{- if not $zone.elasticIPAllocationID }}
resource "aws_eip" "eip_natgw_z{{ $index }}" {
  vpc = true

  tags = {
    Name = "{{ $.clusterName }}-eip-natgw-z{{ $index }}"
    "kubernetes.io/cluster/{{ $.clusterName }}"  = "1"
  }
}
{{- end }}

resource "aws_nat_gateway" "natgw_z{{ $index }}" {
  {{ if not $zone.elasticIPAllocationID -}}
  allocation_id = aws_eip.eip_natgw_z{{ $index }}.id
  {{- else -}}
  allocation_id = "{{ $zone.elasticIPAllocationID }}"
  {{- end }}
  subnet_id     = aws_subnet.public_utility_z{{ $index }}.id

  tags = {
    Name = "{{ $.clusterName }}-natgw-z{{ $index }}"
    "kubernetes.io/cluster/{{ $.clusterName }}"  = "1"
  }
}

resource "aws_route_table" "routetable_private_utility_z{{ $index }}" {
  vpc_id = {{ $.vpc.id }}

  timeouts {
    create = "5m"
  }

{{ commonTagsWithSuffix $.clusterName (print "private-" $zone.name) | indent 2 }}
}

resource "aws_route" "private_utility_z{{ $index }}_nat" {
  route_table_id         = aws_route_table.routetable_private_utility_z{{ $index }}.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.natgw_z{{ $index }}.id

  timeouts {
    create = "5m"
  }
}

resource "aws_route_table_association" "routetable_private_utility_z{{ $index }}_association_private_utility_z{{ $index }}" {
  subnet_id      = aws_subnet.private_utility_z{{ $index }}.id
  route_table_id = aws_route_table.routetable_private_utility_z{{ $index }}.id
}

resource "aws_route_table_association" "routetable_main_association_public_utility_z{{ $index }}" {
  subnet_id      = aws_subnet.public_utility_z{{ $index }}.id
  route_table_id = aws_route_table.routetable_main.id
}

resource "aws_route_table_association" "routetable_private_utility_z{{ $index }}_association_nodes_z{{ $index }}" {
  subnet_id      = aws_subnet.nodes_z{{ $index }}.id
  route_table_id = aws_route_table.routetable_private_utility_z{{ $index }}.id
}
{{end}}

//=====================================================================
//= IAM instance profiles
//=====================================================================

resource "aws_iam_role" "nodes" {
  name = "{{ .clusterName }}-nodes"
  path = "/"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "nodes" {
  name = "{{ .clusterName }}-nodes"
  role = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy" "nodes" {
  name = "{{ .clusterName }}-nodes"
  role = aws_iam_role.nodes.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances"
      ],
      "Resource": [
        "*"
      ]
    }{{ if .enableECRAccess }},
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:BatchGetImage"
      ],
      "Resource": [
        "*"
      ]
    }{{ end }}
  ]
}
EOF
}

//=====================================================================
//= EC2 Key Pair
//=====================================================================

resource "aws_key_pair" "kubernetes" {
  key_name   = "{{ .clusterName }}-ssh-publickey"
  public_key = "{{ .sshPublicKey }}"
}

//=====================================================================
//= Output variables
//=====================================================================

output "{{ .outputKeys.vpcIdKey }}" {
  value = {{ .vpc.id }}
}

output "{{ .outputKeys.iamInstanceProfileNodes }}" {
  value = aws_iam_instance_profile.nodes.name
}

output "{{ .outputKeys.sshKeyName }}" {
  value = aws_key_pair.kubernetes.key_name
}

output "{{ .outputKeys.securityGroupsNodes }}" {
  value = aws_security_group.nodes.id
}

output "{{ .outputKeys.nodesRole }}" {
  value = aws_iam_role.nodes.arn
}
