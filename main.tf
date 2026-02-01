locals {
  reg-1-zone-a = "${var.region_1}-a"
  reg-1-zone-b = "${var.region_1}-b"
  reg-2-zone-a = "${var.region_2}-a"
  reg-2-zone-b = "${var.region_2}-b"  
}

provider "google" {
}

resource "random_id" "id" {
  byte_length = 4
  prefix      = "sg"
}
