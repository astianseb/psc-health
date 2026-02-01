resource "google_project" "consumer" {
  org_id    = var.parent.parent_type == "organizations" ? var.parent.parent_id : null
  folder_id = var.parent.parent_type == "folders" ? var.parent.parent_id : null

  name                = "${var.consumer_project_name}-${random_id.id.hex}"
  project_id          = "${var.consumer_project_name}-${random_id.id.hex}"
  billing_account     = var.billing_account
  auto_create_network = false
}


# data "google_project" "consumer" {
#     project_id = var.consumer_project_id
# }

resource "google_project_service" "consumer" {
  for_each = toset([
    "compute.googleapis.com",
    "servicedirectory.googleapis.com",
    "dns.googleapis.com",
    "certificatemanager.googleapis.com"
  ])

  service            = each.key
  project            = google_project.consumer.project_id
  disable_on_destroy = false
}

####### VPC NETWORK

resource "google_compute_network" "consumer_vpc_network" {
  name                    = "vnet-consumer"
  auto_create_subnetworks = false
  mtu                     = 1460
  project                 = google_project.consumer.project_id
}


####### VPC SUBNETS

resource "google_compute_subnetwork" "consumer_subnet_1" {
  name          = "subnet-1"
  project       = google_project.consumer.project_id
  ip_cidr_range = "192.168.11.0/24"
  network       = google_compute_network.consumer_vpc_network.id
  
  region        = var.region_1
}

resource "google_compute_subnetwork" "consumer_subnet_2" {
  name          = "subnet-2"
  project       = google_project.consumer.project_id
  ip_cidr_range = "192.168.12.0/24"
  network       = google_compute_network.consumer_vpc_network.id

  region = var.region_2
}

resource "google_compute_subnetwork" "consumer_proxy_subnet_1" {
  name          = "proxy-subnet-1"
  project       = google_project.consumer.project_id
  region        = var.region_1
  ip_cidr_range = "10.10.101.0/24"
  network       = google_compute_network.consumer_vpc_network.id
  purpose       = "GLOBAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

resource "google_compute_subnetwork" "consumer_proxy_subnet_2" {
  name          = "proxy-subnet-1"
  project       = google_project.consumer.project_id
  region        = var.region_2
  ip_cidr_range = "10.10.102.0/24"
  network       = google_compute_network.consumer_vpc_network.id
  purpose       = "GLOBAL_MANAGED_PROXY"
  role          = "ACTIVE"
}



####### FIREWALL

resource "google_compute_firewall" "consumer_fw_allow_internal" {
  name      = "sg-allow-internal"
  project   = google_project.consumer.project_id
  network   = google_compute_network.consumer_vpc_network.name
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
      google_compute_subnetwork.consumer_subnet_1.ip_cidr_range]
}

resource "google_compute_firewall" "consumer_fw_allow_ssh" {
  name      = "sg-allow-ssh"
  project   = google_project.consumer.project_id
  network   = google_compute_network.consumer_vpc_network.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}


#### NAT

resource "google_compute_router" "consumer_router" {
  name    = "nat-router"
  project = google_project.consumer.project_id
  network = google_compute_network.consumer_vpc_network.id

  region = var.region_1


  bgp {
    asn = 64514
  }
}

resource "google_compute_router_nat" "consumer_nat" {
  name                               = "my-router-nat"
  project                            = google_project.consumer.project_id
  router                             = google_compute_router.consumer_router.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  region = var.region_1


  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}


################### HTTPS BACKEND #######################

# Self-signed regional SSL certificate for testing
resource "tls_private_key" "consumer_1" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_private_key" "consumer_2" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "consumer_1" {
  private_key_pem = tls_private_key.consumer_1.private_key_pem

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

  dns_names = ["1.consumer.com"]

  subject {
    common_name  = "1.consumer.com"
    organization = "SG Test Consumer 1"
  }
}

resource "tls_self_signed_cert" "consumer_2" {
  private_key_pem = tls_private_key.consumer_2.private_key_pem

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

  dns_names = ["2.consumer.com"]

  subject {
    common_name  = "2.consumer.com"
    organization = "SG Test Consumer 2"
  }
}

resource "google_certificate_manager_certificate" "consumer_1" {
  project     = google_project.consumer.project_id

  name        = "consumer-1"
  description = "Consumer 1"
  scope       = "ALL_REGIONS"
  self_managed {
    pem_certificate = tls_self_signed_cert.consumer_1.cert_pem
    pem_private_key = tls_private_key.consumer_1.private_key_pem
  }
}

resource "google_certificate_manager_certificate" "consumer_2" {
  project     = google_project.consumer.project_id

  name        = "consumer-2"
  description = "Consumer 2"
  scope       = "ALL_REGIONS"
  self_managed {
    pem_certificate = tls_self_signed_cert.consumer_2.cert_pem
    pem_private_key = tls_private_key.consumer_2.private_key_pem
  }
}


resource "google_compute_region_network_endpoint_group" "consumer_1" {
  name                  = "psc-neg-1"
  project               = google_project.consumer.project_id
  region                = var.region_1
  network_endpoint_type = "PRIVATE_SERVICE_CONNECT"
  psc_target_service    = google_compute_service_attachment.producer_1.id
  
  network    = google_compute_network.consumer_vpc_network.name
  subnetwork = google_compute_subnetwork.consumer_subnet_1.self_link
}


resource "google_compute_region_network_endpoint_group" "consumer_2" {
  name                  = "psc-neg-2"
  project               = google_project.consumer.project_id
  region                = var.region_2
  network_endpoint_type = "PRIVATE_SERVICE_CONNECT"
  psc_target_service    = google_compute_service_attachment.producer_2.id
  
  network    = google_compute_network.consumer_vpc_network.name
  subnetwork = google_compute_subnetwork.consumer_subnet_2.self_link
}


resource "google_compute_backend_service" "consumer" {
  name                            = "consumer"
  project                         = google_project.consumer.project_id
  connection_draining_timeout_sec = 0
  load_balancing_scheme           = "INTERNAL_MANAGED"
  port_name                       = "my-https"
  protocol                        = "HTTPS"
  session_affinity                = "NONE"
  timeout_sec                     = 30
  
  backend {
    group           = google_compute_region_network_endpoint_group.consumer_1.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }

  backend {
    group           = google_compute_region_network_endpoint_group.consumer_2.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
}


resource "google_compute_url_map" "consumer" {
  name            = "consumer"
  project         = google_project.consumer.project_id
  default_service = google_compute_backend_service.consumer.self_link
}

resource "google_compute_target_https_proxy" "consumer" {
  name    = "consumer"
  project = google_project.consumer.project_id
  url_map = google_compute_url_map.consumer.self_link

  certificate_manager_certificates = [google_certificate_manager_certificate.consumer_1.id,
                                      google_certificate_manager_certificate.consumer_2.id]
    
}


resource "google_compute_global_forwarding_rule" "consumer_1" {
  name                  = "consumer-1"
  project               = google_project.consumer.project_id
 # allow_global_access   = true
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  network               = google_compute_network.consumer_vpc_network.name
  port_range            = "443"
  subnetwork            = google_compute_subnetwork.consumer_subnet_1.self_link
  target                = google_compute_target_https_proxy.consumer.self_link

}


resource "google_compute_global_forwarding_rule" "consumer_2" {
  name                  = "consumer-2"
  project               = google_project.consumer.project_id
 # allow_global_access   = true
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  network               = google_compute_network.consumer_vpc_network.name
  port_range            = "443"
  subnetwork            = google_compute_subnetwork.consumer_subnet_2.self_link
  target                = google_compute_target_https_proxy.consumer.self_link

}



######################## SIEGE HOST ################

# Instance to host siege (testing tool for LB)
# usage: siege -i --concurrent=50 http://<lb-ip>


resource "google_compute_instance" "consumer_siege_host" {
  name         = "consumer-siege-host"
  machine_type = "e2-medium"
  zone         = local.reg-1-zone-a
  project      = google_project.consumer.project_id

  tags = ["siege"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network    = google_compute_network.consumer_vpc_network.name
    subnetwork = google_compute_subnetwork.consumer_subnet_1.self_link
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