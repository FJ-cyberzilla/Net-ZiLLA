# deployments/terraform/main.tf
resource "kubernetes_deployment" "analyzer" {
  metadata {
    name = "sms-analyzer"
  }
  spec {
    replicas = 3
    selector {
      match_labels = {
        app = "sms-analyzer"
      }
    }
    template {
      metadata {
        labels = {
          app = "sms-analyzer"
        }
      }
      spec {
        container {
          image = "sms-analyzer:latest"
          name  = "analyzer"
          port {
            container_port = 8080
          }
        }
      }
    }
  }
}
