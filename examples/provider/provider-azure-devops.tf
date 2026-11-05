# In an Azure DevOps job, the OIDC token of a service connection; on a
# workstation (no SYSTEM_OIDCREQUESTURI), azure_identity with the Azure CLI
# login of the person running Terraform. Same configuration in both places.
provider "dnsgate" {
  endpoint = "https://dns-gate.example.com"

  auth {
    # service_connection_id defaults to DNSGATE_ADO_SERVICE_CONNECTION_ID,
    # for example from a variable group of the pipeline.
    azure_devops {}
    azure_identity {
      scope = "api://dns-gate/.default"
    }
  }
}
