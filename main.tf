# AWS Provider
provider "aws" {
   region = "ap-south-1"
   profile = "apeksh"
}

# Generate new private key 
resource "tls_private_key" "my_key" {
  algorithm = "RSA"
}

# Generate a key-pair with above key
resource "aws_key_pair" "deployer" {
  key_name   = "deploy-key"
  public_key = tls_private_key.my_key.public_key_openssh
}

# Deafult VPC
resource "aws_default_vpc" "default" {
  tags = {
    Name = "Default VPC"
  }
}

# Creating a new security group with ssh and http inbound rules
resource "aws_security_group" "my_security_group" {
  name        = "my_security_group"
  description = "Allow SSH and HTTP"
  vpc_id      = aws_default_vpc.default.id                      

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

 ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

# Creating new ebs volume for backup
resource "aws_ebs_volume" "backup" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1
  tags = {
    Name = "backup"
  }
}

# Attaching above volume with ec2 instance
resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.backup.id
  instance_id = aws_instance.web.id
  force_detach = true
}

# EC2 instance 
resource "aws_instance" "web" {
  depends_on = [aws_s3_bucket.my_bucket]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = aws_key_pair.deployer.key_name
  security_groups = [aws_security_group.my_security_group.name]
  user_data = <<-EOF
          #! /bin/bash
	  sudo yum install httpd php git -y
	  sudo systemctl start httpd
          sudo systemctl enable httpd
	  	EOF
  tags = {
     Name = "WEB"
  } 

 provisioner "local-exec" {
  command = "echo ${aws_instance.web.public_ip} > publicIP.txt"
 }
}


# For creating partition, formatting, mounting and cloning our repo
resource "null_resource" "mounting" {
  depends_on = [aws_volume_attachment.ebs_att]
   connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.my_key.private_key_pem
    host     = aws_instance.web.public_ip
   }
  provisioner "remote-exec" {
    inline = [
      "sudo echo -e 'n\n\n\n\n\nw' | sudo fdisk ${aws_volume_attachment.ebs_att.device_name} ",
      "sudo mkfs.ext4 ${aws_volume_attachment.ebs_att.device_name}" ,
      "sudo mount ${aws_volume_attachment.ebs_att.device_name} /var/www/html ",
      "sudo rm -rf /var/www/html/* " ,
      "sudo git clone https://github.com/Apeksh742/EC2_instance_with_terraform.git /var/www/html" ,
    ]
  }
}


# Creating New Origin Access Identity
resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "new-acess-identity"
}
 

# Creating new S3 bucket 
resource "aws_s3_bucket" "my_bucket" {

  bucket = "mybucket5g.com"  #Enter unique name here
  acl    = "private"
  tags = {
    Name        = "My bucket"
  }
}


# Bucket Policy for allowing acess to cloudfront distribution
resource "aws_s3_bucket_policy" "my_bucket_policy" {
  bucket = aws_s3_bucket.my_bucket.id

  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${aws_cloudfront_origin_access_identity.origin_access_identity.id}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::${aws_s3_bucket.my_bucket.bucket}/*"
        }
    ]
}
POLICY
}

# Storing images from github repo so that later s3 objects are uploaded
resource "null_resource" "repo" {
 depends_on = [] 
 provisioner "local-exec" {
  command=<<EOT
    mkdir project
    git clone https://github.com/Apeksh742/EC2_instance_with_terraform.git ./project
  EOT
 }
}

# Storing Objects in S3 bucket 
resource "aws_s3_bucket_object" "object" {
  acl = "public-read"
  depends_on = [aws_s3_bucket.my_bucket]
  bucket = aws_s3_bucket.my_bucket.id
  key    = "WALLPAPER.jpg"
  source = "./project/images/WALLPAPER2.jpg"   # source will be different for different objects
}


locals {
  s3_origin_id = "myS3Origin"
}


# Creating CloudFront Distribution 
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.my_bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  
s3_origin_config {
  origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
    }

  }
 
  enabled             = true
  is_ipv6_enabled     = true

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  tags = {
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}


# Retrieve CloudFront Domain 
resource "null_resource" "CloudFront_Domain" {
  depends_on = [aws_cloudfront_distribution.s3_distribution]

  provisioner "local-exec" {
    command = "echo ${aws_cloudfront_distribution.s3_distribution.domain_name} > CloudFrontURL.txt" 
  }
}

resource "null_resource" "final_resource" {
 depends_on = [aws_cloudfront_distribution.s3_distribution] 
 provisioner "local-exec" {
  command = <<EOT
   rd /s /q "project/"
  EOT
 }
}
