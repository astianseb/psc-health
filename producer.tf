
############ PROJECT ###############

resource "google_project" "producer" {
  org_id    = var.parent.parent_type == "organizations" ? var.parent.parent_id : null
  folder_id = var.parent.parent_type == "folders" ? var.parent.parent_id : null

  name                = "${var.producer_project_name}-${random_id.id.hex}"
  project_id          = "${var.producer_project_name}-${random_id.id.hex}"
  billing_account     = var.billing_account
  auto_create_network = false
}

# data "google_project" "producer" {
#     project_id = var.producer_project_id
# }




resource "google_project_service" "producer_service" {
  for_each = toset([
    "compute.googleapis.com",
    "servicedirectory.googleapis.com",
    "dns.googleapis.com"
  ])

  service            = each.key
  project            = google_project.producer.project_id
  disable_on_destroy = false
}

####### VPC NETWORK

resource "google_compute_network" "producer_vpc_network" {
  name                    = "vnet-producer"
  auto_create_subnetworks = false
  mtu                     = 1460
  project                 = google_project.producer.project_id
}


####### VPC SUBNETS

resource "google_compute_subnetwork" "producer_subnet_1" {
  name          = "subnet-1"
  project       = google_project.producer.project_id
  ip_cidr_range = "10.10.20.0/24"
  region        = var.region_1
  network       = google_compute_network.producer_vpc_network.id
}

resource "google_compute_subnetwork" "producer_subnet_2" {
  name          = "subnet-2"
  project       = google_project.producer.project_id
  ip_cidr_range = "10.10.40.0/24"
  region        = var.region_2
  network       = google_compute_network.producer_vpc_network.id
}

resource "google_compute_subnetwork" "producer_1" {
  name          = "proxy-subnet-1"
  project       = google_project.producer.project_id
  region        = var.region_1
  ip_cidr_range = "10.10.201.0/24"
  network       = google_compute_network.producer_vpc_network.id
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"

}

resource "google_compute_subnetwork" "producer_2" {
  name          = "proxy-subnet-2"
  project       = google_project.producer.project_id
  region        = var.region_2
  ip_cidr_range = "10.10.202.0/24"
  network       = google_compute_network.producer_vpc_network.id
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"



}

####### FIREWALL

resource "google_compute_firewall" "producer_fw_allow_internal" {
  name      = "sg-allow-internal"
  project   = google_project.producer.project_id
  network   = google_compute_network.producer_vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [
    google_compute_subnetwork.producer_subnet_1.ip_cidr_range,
    google_compute_subnetwork.producer_subnet_2.ip_cidr_range]
}

resource "google_compute_firewall" "producer_fw_allow_ssh" {
  name      = "sg-allow-ssh"
  project   = google_project.producer.project_id
  network   = google_compute_network.producer_vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "producer_fw_app_allow_http" {
  name      = "sg-app-allow-http"
  project   = google_project.producer.project_id
  network   = google_compute_network.producer_vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80", "8080"]
  }
  target_tags   = ["lb-backend"]
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "producer_fw_app_allow_health_check" {
  name      = "sg-app-allow-health-check"
  project   = google_project.producer.project_id
  network   = google_compute_network.producer_vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
  }
  target_tags   = ["lb-backend"]
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
}

#### NAT

resource "google_compute_router" "producer_1" {
  name    = "producer-1"
  project = google_project.producer.project_id
  network = google_compute_network.producer_vpc_network.id
  region  = var.region_1

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "producer_1" {
  name                               = "producer-1"
  project                            = google_project.producer.project_id
  router                             = google_compute_router.producer_1.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  
  region = var.region_1

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_router" "producer_2" {
  name    = "producer-2"
  project = google_project.producer.project_id
  network = google_compute_network.producer_vpc_network.id
  region  = var.region_2

  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "producer_2" {
  name                               = "producer-2"
  project                            = google_project.producer.project_id
  router                             = google_compute_router.producer_2.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  region = var.region_2

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}




# Self-signed regional SSL certificate for testing
resource "tls_private_key" "producer_1" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Self-signed regional SSL certificate for testing
resource "tls_private_key" "producer_2" {
  algorithm = "RSA"
  rsa_bits  = 2048
}


resource "tls_self_signed_cert" "producer_1" {
  private_key_pem = tls_private_key.producer_1.private_key_pem

  # Certificate expires after 48 hours.
  validity_period_hours = 48

  # Generate a new certificate if Terraform is run within three
  # hours of the certificate's expiration time.
  early_renewal_hours = 3

  # Reasonable set of uses for a server SSL certificate.
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  dns_names = ["1.producer.com"]

  subject {
    common_name  = "sg-1.producer.com"
    organization = "SG Producer 1"
  }
}

resource "tls_self_signed_cert" "producer_2" {
  private_key_pem = tls_private_key.producer_2.private_key_pem

  # Certificate expires after 48 hours.
  validity_period_hours = 48

  # Generate a new certificate if Terraform is run within three
  # hours of the certificate's expiration time.
  early_renewal_hours = 3

  # Reasonable set of uses for a server SSL certificate.
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  dns_names = ["2.producer.com"]

  subject {
    common_name  = "sg-2.producer.com"
    organization = "SG Producer 2"
  }
}

resource "google_compute_region_ssl_certificate" "producer_1" {
  project     = google_project.producer.project_id
  name_prefix = "my-cert-1-"
  private_key = tls_private_key.producer_1.private_key_pem
  certificate = tls_self_signed_cert.producer_1.cert_pem
  region      = var.region_1
  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_region_ssl_certificate" "producer_2" {
  project     = google_project.producer.project_id
  name_prefix = "my-cert-2-"
  private_key = tls_private_key.producer_2.private_key_pem
  certificate = tls_self_signed_cert.producer_2.cert_pem
  region      = var.region_2
  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_region_health_check" "tcp_health_check_1" {
  name               = "tcp-health-check-1"
  project            = google_project.producer.project_id
  region             = var.region_1 
  timeout_sec        = 1
  check_interval_sec = 1


  tcp_health_check {
    port = "80"
  }
}

resource "google_compute_region_health_check" "tcp_health_check_2" {
  name               = "tcp-health-check-2"
  project            = google_project.producer.project_id
  region             = var.region_2 
  timeout_sec        = 1
  check_interval_sec = 1


  tcp_health_check {
    port = "80"
  }
}



// ------------- Instance Group 1 --------------
resource "google_compute_instance_template" "tmpl_instance_group_1" {
  name                 = "instance-group-1"
  project              = google_project.producer.project_id
  description          = "SG instance group of preemptible hosts"
  instance_description = "description assigned to instances"
  machine_type         = "e2-medium"
  can_ip_forward       = false
  tags                 = ["lb-backend"]

  region = var.region_1

  scheduling {
    preemptible       = true
    automatic_restart = false

  }
  
  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  // Create a new boot disk from an image
  disk {
    source_image = "debian-cloud/debian-11"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    network            = google_compute_network.producer_vpc_network.name
    subnetwork         = google_compute_subnetwork.producer_subnet_1.name
    subnetwork_project = google_project.producer.project_id
  }

  metadata = {
#    startup-script-url = "gs://cloud-training/gcpnet/ilb/startup.sh"
    startup-script-url = "https://raw.githubusercontent.com/astianseb/sg-helper-scripts/refs/heads/main/startup.sh"

  }
}

#MIG-a
resource "google_compute_instance_group_manager" "grp_instance_group_1" {
  name               = "instance-group-1"
  project            = google_project.producer.project_id
  base_instance_name = "mig-1"
  zone               = local.reg-1-zone-a
  version {
    instance_template = google_compute_instance_template.tmpl_instance_group_1.id
  }

  auto_healing_policies {
    health_check      = google_compute_region_health_check.tcp_health_check_1.id
    initial_delay_sec = 300
  }
}

resource "google_compute_autoscaler" "autoscaler_1" {
  name    = "my-autoscaler-1"
  project = google_project.producer.project_id
  zone    = local.reg-1-zone-a
  target  = google_compute_instance_group_manager.grp_instance_group_1.id

  autoscaling_policy {
    max_replicas    = 5
    min_replicas    = 1
    cooldown_period = 45

    cpu_utilization {
      target = 0.8
    }
  }
}


//----------------Instance Group 2----------------


resource "google_compute_instance_template" "tmpl_instance_group_2" {
  name                 = "instance-group-2"
  project              = google_project.producer.project_id
  description          = "SG instance group of preemptible hosts"
  instance_description = "description assigned to instances"
  machine_type         = "e2-medium"
  can_ip_forward       = false
  tags                 = ["lb-backend"]

  region = var.region_2

  scheduling {
    preemptible       = true
    automatic_restart = false

  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  disk {
    source_image = "debian-cloud/debian-11"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    network            = google_compute_network.producer_vpc_network.name
    subnetwork         = google_compute_subnetwork.producer_subnet_2.name
    subnetwork_project = google_project.producer.project_id
  }

  metadata = {
#    startup-script-url = "gs://cloud-training/gcpnet/ilb/startup.sh"
    startup-script-url = "https://raw.githubusercontent.com/astianseb/sg-helper-scripts/refs/heads/main/startup.sh"

  }
}

resource "google_compute_instance_group_manager" "grp_instance_group_2" {
  name               = "instance-group-2"
  project            = google_project.producer.project_id
  base_instance_name = "mig-2"
  zone               = local.reg-2-zone-a
  version {
    instance_template = google_compute_instance_template.tmpl_instance_group_2.id
  }

  auto_healing_policies {
    health_check      = google_compute_region_health_check.tcp_health_check_2.id
    initial_delay_sec = 300
  }
}

resource "google_compute_autoscaler" "autoscaler_2" {
  name    = "my-autoscaler-2"
  project = google_project.producer.project_id
  zone    = local.reg-2-zone-a
  target  = google_compute_instance_group_manager.grp_instance_group_2.id

  autoscaling_policy {
    max_replicas    = 5
    min_replicas    = 1
    cooldown_period = 45

    cpu_utilization {
      target = 0.8
    }
  }
}


########## LB - 1 ############


# forwarding rule
resource "google_compute_forwarding_rule" "producer_1" {
  name                  = "producer-1"
  provider              = google-beta
  region                = var.region_1
  project               = google_project.producer.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_region_target_https_proxy.producer_1.id
 # ip_address            = google_compute_address.default.id
  network               = google_compute_network.producer_vpc_network.id
  subnetwork            = google_compute_subnetwork.producer_subnet_1.id
  allow_global_access   = true

}

# http proxy
resource "google_compute_region_target_https_proxy" "producer_1" {
  name     = "producer-1"
  provider = google-beta
  region   = var.region_1
  project  = google_project.producer.project_id
  url_map  = google_compute_region_url_map.producer_1.id
  
  ssl_certificates = [google_compute_region_ssl_certificate.producer_1.self_link]

}

# url map
resource "google_compute_region_url_map" "producer_1" {
  name            = "producer-1"
  provider        = google-beta
  region          = var.region_1
  project         = google_project.producer.project_id
  default_service = google_compute_region_backend_service.producer_1.id
}


# HTTP regional load balancer (envoy based)
resource "google_compute_region_backend_service" "producer_1" {
  name                     = "producer-1"
  provider                 = google-beta
  region                   = var.region_1
  project                  = google_project.producer.project_id
  protocol                 = "HTTP"
  port_name                = "my-port-1"
  load_balancing_scheme    = "INTERNAL_MANAGED"
  timeout_sec              = 10
  health_checks            = [google_compute_region_health_check.tcp_health_check_1.id]
  backend {
    group           = google_compute_instance_group_manager.grp_instance_group_1.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
}


############ PUBLISH ########

resource "google_compute_subnetwork" "psc_producer_1" {
  name          = "psc-1"
  region        = var.region_1
  project       = google_project.producer.project_id
  ip_cidr_range = "10.10.101.0/24"
  network       = google_compute_network.producer_vpc_network.id
  purpose       =  "PRIVATE_SERVICE_CONNECT"

}

resource "google_compute_service_attachment" "producer_1" {
  name        = "producer-1"
  region      = var.region_1
  project     = google_project.producer.project_id
  description = "SA for Producer-1"

 # domain_names             = ["gcp.tfacc.hashicorptest.com."]
  enable_proxy_protocol    = false
  connection_preference    = "ACCEPT_AUTOMATIC"
  nat_subnets              = [google_compute_subnetwork.psc_producer_1.id]
  target_service           = google_compute_forwarding_rule.producer_1.id
}

########## LB - 2 ############


# forwarding rule
resource "google_compute_forwarding_rule" "producer_2" {
  name                  = "producer-2"
  provider              = google-beta
  region                = var.region_2
  project               = google_project.producer.project_id
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_region_target_https_proxy.producer_2.id
 # ip_address            = google_compute_address.default.id
  network               = google_compute_network.producer_vpc_network.id
  subnetwork            = google_compute_subnetwork.producer_subnet_2.id
  allow_global_access   = true

}

# http proxy
resource "google_compute_region_target_https_proxy" "producer_2" {
  name     = "producer-2"
  provider = google-beta
  region   = var.region_2
  project  = google_project.producer.project_id
  url_map  = google_compute_region_url_map.producer_2.id
  
  ssl_certificates = [google_compute_region_ssl_certificate.producer_2.self_link]

}

# url map
resource "google_compute_region_url_map" "producer_2" {
  name            = "producer-2"
  provider        = google-beta
  region          = var.region_2
  project         = google_project.producer.project_id
  default_service = google_compute_region_backend_service.producer_2.id
}


# HTTP regional load balancer (envoy based)
resource "google_compute_region_backend_service" "producer_2" {
  name                     = "producer-2"
  provider                 = google-beta
  region                   = var.region_2
  project                  = google_project.producer.project_id
  protocol                 = "HTTP"
  port_name                = "my-port-2"
  load_balancing_scheme    = "INTERNAL_MANAGED"
  timeout_sec              = 10
  health_checks            = [google_compute_region_health_check.tcp_health_check_2.id]
  backend {
    group           = google_compute_instance_group_manager.grp_instance_group_2.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
}


############ PUBLISH ########

resource "google_compute_subnetwork" "psc_producer_2" {
  name          = "psc-2"
  region        = var.region_2
  project       = google_project.producer.project_id
  ip_cidr_range = "10.10.102.0/24"
  network       = google_compute_network.producer_vpc_network.id
  purpose       =  "PRIVATE_SERVICE_CONNECT"

}

resource "google_compute_service_attachment" "producer_2" {
  name        = "producer-2"
  region      = var.region_2
  project     = google_project.producer.project_id
  description = "SA for Producer-2"

 # domain_names             = ["gcp.tfacc.hashicorptest.com."]
  enable_proxy_protocol    = false
  connection_preference    = "ACCEPT_AUTOMATIC"
  nat_subnets              = [google_compute_subnetwork.psc_producer_2.id]
  target_service           = google_compute_forwarding_rule.producer_2.id
}


############### PSC HEALTH #####################

###### REGION 1 ######

resource "google_compute_region_health_aggregation_policy" "producer_1" {
  provider    = google-beta
  project     = google_project.producer.project_id
  region      = var.region_1

  name        = "producer-1-hap"
  description = "Example health aggregation policy basic"
}

resource "google_compute_region_health_source" "producer_1" {
  provider      = google-beta
  project       = google_project.producer.project_id
  region        = var.region_1
 
  name                      = "producer-1-hs"
  description               = "Example health source basic"
  source_type               = "BACKEND_SERVICE"
  sources                   = [google_compute_region_backend_service.producer_1.id]
  health_aggregation_policy = google_compute_region_health_aggregation_policy.producer_1.id
}

resource "google_compute_region_composite_health_check" "producer_1" {
  provider      = google-beta
  project       = google_project.producer.project_id
  region        = var.region_1

  name               = "producer-1-chc"
  description        = "test regional composite health check resource"
  health_sources     = [google_compute_region_health_source.producer_1.id]
  health_destination = google_compute_forwarding_rule.producer_1.id
}


###### REGION 2 ######


resource "google_compute_region_health_aggregation_policy" "producer_2" {
  provider    = google-beta
  project     = google_project.producer.project_id
  region      = var.region_2

  name        = "producer-2-hap"
  description = "Example health aggregation policy basic"
}

resource "google_compute_region_health_source" "producer_2" {
  provider      = google-beta
  project       = google_project.producer.project_id
  region        = var.region_2
 
  name                      = "producer-2-hs"
  description               = "Example health source basic"
  source_type               = "BACKEND_SERVICE"
  sources                   = [google_compute_region_backend_service.producer_2.id]
  health_aggregation_policy = google_compute_region_health_aggregation_policy.producer_2.id
}

resource "google_compute_region_composite_health_check" "producer_2" {
  provider      = google-beta
  project       = google_project.producer.project_id
  region        = var.region_2

  name               = "producer-2-chc"
  description        = "test regional composite health check resource"
  health_sources     = [google_compute_region_health_source.producer_2.id]
  health_destination = google_compute_forwarding_rule.producer_2.id
}


############### SIEGE HOST #####################

# Instance to host siege (testing tool for LB)
# usage: siege -i --concurrent=50 http://<lb-ip>
#

resource "google_compute_instance" "producer_siege_host" {
  name         = "producer-siege-host"
  machine_type = "e2-medium"
  zone         = local.reg-1-zone-a
  project      = google_project.producer.project_id

  tags = ["siege"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.producer_vpc_network.name
    subnetwork = google_compute_subnetwork.producer_subnet_1.self_link
  }

  scheduling {
    preemptible       = true
    automatic_restart = false
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  metadata = {
    enable-oslogin = true
  }


  metadata_startup_script = <<-EOF1
      #! /bin/bash
      set -euo pipefail

      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y siege
     EOF1

}