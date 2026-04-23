# ---------------------------------------------------------------------------
# Custom org-policy constraints sourced from
# fast-stage-0/datasets/hardened/organization/custom-constraints/
# ---------------------------------------------------------------------------

module "org_policy" {
  source = "./modules/org-policy"

  org_id = var.org_id

  custom_constraints = {
    "custom.accesscontextmanagerDisableBridgePerimetersV4" = {
      resource_types = ["accesscontextmanager.googleapis.com/ServicePerimeter"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.perimeterType == 'PERIMETER_TYPE_BRIDGE'"
      action_type    = "DENY"
      display_name   = "Deny usage of perimeter bridges"
      description    = "Ensure no perimeter bridges are used. Instead, use ingress and egress rules."
    }

    "custom.cloudbuildDisableWorkerPoolExternalIPV4" = {
      resource_types = ["cloudbuild.googleapis.com/WorkerPool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "(resource.privatePoolV1Config.networkConfig.egressOption != \"NO_PUBLIC_EGRESS\")"
      action_type    = "DENY"
      display_name   = "Deny unauthorized worker pools external ip used for each build"
      description    = "Ensure no unauthorized worker pools external ip used for each build"
    }

    "custom.cloudkmsAllowedAlgorithmsV4" = {
      resource_types = ["cloudkms.googleapis.com/CryptoKey"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "has(resource.versionTemplate.algorithm) && resource.versionTemplate.algorithm in [\n  'GOOGLE_SYMMETRIC_ENCRYPTION',\n  'RSA_SIGN_PSS_2048_SHA256',\n  'RSA_SIGN_PSS_3072_SHA256',\n  'RSA_SIGN_PSS_4096_SHA256',\n  'RSA_DECRYPT_OAEP_2048_SHA256',\n  'RSA_DECRYPT_OAEP_4096_SHA256',\n  'RSA_DECRYPT_OAEP_2048_SHA1',\n  'RSA_DECRYPT_OAEP_4096_SHA1'\n] == false"
      action_type    = "DENY"
      display_name   = "Require Cloud KMS keys algorithm to be configured correctly"
      description    = "Ensure the algorithm for Cloud KMS keys is configured correctly"
    }

    "custom.cloudkmsAllowedProtectionLevelV4" = {
      resource_types = ["cloudkms.googleapis.com/CryptoKey"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "has(resource.versionTemplate.protectionLevel) && resource.versionTemplate.protectionLevel in [\"SOFTWARE\"] == false"
      action_type    = "DENY"
      display_name   = "Require Cloud KMS keys protection level to be configured correctly"
      description    = "Ensure the protection level for Cloud KMS keys is configured correctly"
    }

    "custom.cloudkmsAllowedRotationPeriodV4" = {
      resource_types = ["cloudkms.googleapis.com/CryptoKey"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "has(resource.rotationPeriod) && resource.rotationPeriod > duration(\"7776000s\")"
      action_type    = "DENY"
      display_name   = "Require Cloud KMS keys to have rotation period configured correctly"
      description    = "Ensure the rotation period for Cloud KMS keys is configured correctly"
    }

    "custom.cloudrunDisableEnvironmentVariablePatternV4" = {
      resource_types = ["run.googleapis.com/Service"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.spec.template.spec.containers.exists(container,\n  container.env.exists(env,\n    [\"[sS][eE][cC][rR][eE][tT]\", \"[kK][eE][yY]\", \"[pP][aA][sS][sS][wW][oO][rR][dD]\", \"[tT][oO][kK][eE][nN]\"].exists(\n      pattern, env.name.matches(pattern)\n    )\n  )\n)"
      action_type    = "DENY"
      display_name   = "Disable usage of certain patterns in Cloud Run Service or Cloud Run Functions environment variables"
      description    = "Enforce that certain patterns are not used in environment variables of Cloud Run Service or Cloud Run Functions"
    }

    "custom.cloudrunJobDisableDefaultServiceAccountV4" = {
      resource_types = ["run.googleapis.com/Job"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.spec.template.spec.template.spec.serviceAccountName.endsWith('@developer.gserviceaccount.com')"
      action_type    = "DENY"
      display_name   = "Disable creation of Cloud Run Job using default service account"
      description    = "Enforce that service account associated with Cloud Run Job use a non-default service account"
    }

    "custom.cloudrunJobRequireBinaryAuthorizationV4" = {
      resource_types = ["run.googleapis.com/Job"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "!('run.googleapis.com/binary-authorization' in resource.metadata.annotations)"
      action_type    = "DENY"
      display_name   = "Disable creation of Cloud Run Job without Binary Authorization"
      description    = "Enforce that Cloud Run Job are using binary authorization"
    }

    "custom.cloudrunServiceDisableDefaultServiceAccountV4" = {
      resource_types = ["run.googleapis.com/Service"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.spec.template.spec.serviceAccountName.endsWith('@developer.gserviceaccount.com')"
      action_type    = "DENY"
      display_name   = "Disable creation of Cloud Run Service using default service account"
      description    = "Enforce that service account associated with Cloud Run Service use a non-default service account"
    }

    "custom.cloudrunServiceRequireBinaryAuthorizationV4" = {
      resource_types = ["run.googleapis.com/Service"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "!('run.googleapis.com/binary-authorization' in resource.metadata.annotations)"
      action_type    = "DENY"
      display_name   = "Disable creation of Cloud Run Service without Binary Authorization"
      description    = "Enforce that Cloud Run Service are using binary authorization"
    }

    "custom.cloudsqlDisablePublicAuthorizedNetworksV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.settings.ipConfiguration.authorizedNetworks.exists(network, network.value == '0.0.0.0/0')"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL database instances to not whitelist all public IP addresses"
      description    = "Ensure That Cloud SQL database instances do not implicitly whitelist all public IP addresses"
    }

    "custom.cloudsqlEnforcePasswordComplexityV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.settings.passwordValidationPolicy.complexity != 'COMPLEXITY_DEFAULT' ||\nresource.settings.passwordValidationPolicy.minLength < 12"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL instances to configure password complexity to COMPLEXITY_DEFAULT"
      description    = "Ensure that Cloud SQL instance is configured with a password complexity to be combination of lowercase, uppercase, numeric, and non-alphanumeric characters"
    }

    "custom.cloudsqlRequireAutomatedBackupV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.settings.backupConfiguration.enabled != true"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL instances to have automated backup enabled"
      description    = "Ensure that Cloud SQL instance have automated backup enabled"
    }

    "custom.cloudsqlRequireHighAvailabilityV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.settings.availabilityType != \"REGIONAL\""
      action_type    = "DENY"
      display_name   = "Require Cloud SQL instances to be configured with high availability"
      description    = "Ensure that Cloud SQL instance is configured with high availability"
    }

    "custom.cloudsqlRequireMySQLDatabaseFlagsV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.databaseVersion.startsWith('MYSQL') && (\n  !resource.settings.databaseFlags.exists(flag,\n    flag.name == 'skip_show_database' && flag.value == 'on'\n  ) ||\n  !resource.settings.databaseFlags.exists(flag,\n    flag.name == 'local_infile' && flag.value == 'off'\n  )\n)"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL for MySQL instance database flags to be configured correctly (e.g skip_show_database, local_infile)"
      description    = "Ensure Cloud SQL for MySQL instance database flags are set correctly (e.g skip_show_database, local_infile)"
    }

    "custom.cloudsqlRequirePointInTimeRecoveryV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "(resource.databaseVersion.contains(\"POSTGRES\")\n  || resource.databaseVersion.contains(\"SQLSERVER\"))\n  && resource.settings.backupConfiguration.pointInTimeRecoveryEnabled == false"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL instances to enable point in time recovery"
      description    = "Ensure that Cloud SQL instance is configure enable point in time recovery in the backup configuration. This setting is possibly for Postgres and SQLServer databases."
    }

    "custom.cloudsqlRequirePostgreSQLDatabaseAdditionalFlagsV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.databaseVersion.startsWith('POSTGRES') && (\n  !resource.settings.databaseFlags.exists(flag, flag.name == 'log_checkpoints' && flag.value == 'on') ||\n  !resource.settings.databaseFlags.exists(flag, flag.name == 'log_executor_stats' && flag.value == 'off') ||\n  !resource.settings.databaseFlags.exists(flag, flag.name == 'log_lock_waits' && flag.value == 'on')\n)"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL for PostgreSQL instance database flags to be configured correctly (e.g log_checkpoints, log_executor_stats, log_lock_waits)"
      description    = "Ensure Cloud SQL for PostgreSQL instance database flags are set correctly (e.g log_checkpoints, log_executor_stats, log_lock_waits)"
    }

    "custom.cloudsqlRequirePostgreSQLDatabaseFlagsV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.databaseVersion.startsWith('POSTGRES') && (\n  !resource.settings.databaseFlags.exists(f, f.name == 'log_connections' && f.value == 'on') ||\n  !resource.settings.databaseFlags.exists(f, f.name == 'log_disconnections' && f.value == 'on') ||\n  !resource.settings.databaseFlags.exists(f, f.name == 'log_min_duration_statement' && f.value == '-1') ||\n  !resource.settings.databaseFlags.exists(f, f.name == 'cloudsql.enable_pgaudit' && f.value == 'on') ||\n  resource.settings.databaseFlags.exists(f, f.name == 'log_error_verbosity' && f.value == 'terse') ||\n  resource.settings.databaseFlags.exists(f, f.name == 'log_statement' && f.value == 'none') ||\n  resource.settings.databaseFlags.exists(f,\n    f.name == 'log_min_messages' && f.value in ['error' , 'log', 'fatal', 'panic']\n  ) ||\n  resource.settings.databaseFlags.exists(f,\n    f.name == 'log_min_error_statement' && f.value in ['log', 'fatal', 'panic']\n  )\n)"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL for PostgreSQL instance database flags to be configured correctly (e.g log_connections)"
      description    = "Ensure Cloud SQL for PostgreSQL instance database flags are set correctly (e.g log_connections)"
    }

    "custom.cloudsqlRequireRootPasswordV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.settings.passwordValidationPolicy.minLength == 0"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL instances to configure root password"
      description    = "Ensure that Cloud SQL instance is configured to use a root password"
    }

    "custom.cloudsqlRequireSQLServerDatabaseFlagsV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.databaseVersion.startsWith('SQLSERVER') && (\n  resource.settings.databaseFlags.exists(flag,\n    flag.name == 'external scripts enabled' && flag.value == 'on'\n  ) ||\n  resource.settings.databaseFlags.exists(flag,\n    flag.name == 'cross db ownership chaining' && flag.value == 'on'\n  ) ||\n  resource.settings.databaseFlags.exists(flag,\n    flag.name == 'contained database authentication' && flag.value == 'on'\n  ) ||\n  resource.settings.databaseFlags.exists(flag,\n    flag.name == 'user connections' && flag.value != '0'\n  ) ||\n  resource.settings.databaseFlags.exists(flag,\n    flag.name == 'user options' && flag.value != '0'\n  ) ||\n  !resource.settings.databaseFlags.exists(flag,\n    flag.name == 'remote access' && flag.value == 'off'\n  ) ||\n  !resource.settings.databaseFlags.exists(flag,\n    flag.name == '3625' && flag.value == 'on'\n  )\n)"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL for SQLServer instance database flags to be configured correctly (e.g external scripts enabled ...)"
      description    = "Ensure Cloud SQL for SQLServer instance database flags are set correctly (e.g external scripts enabled ...)"
    }

    "custom.cloudsqlRequireSSLConnectionV4" = {
      resource_types = ["sqladmin.googleapis.com/Instance"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.settings.ipConfiguration.sslMode in ['ENCRYPTED_ONLY', 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED'] == false"
      action_type    = "DENY"
      display_name   = "Require Cloud SQL instances to allow only connections that are encrypted with SSL/TLS"
      description    = "Ensure that Cloud SQL instance is configured to allow only connections that are encrypted with SSL/TLS"
    }

    "custom.dataprocDisableDefaultServiceAccountV4" = {
      resource_types = ["dataproc.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "has(resource.config.gceClusterConfig.serviceAccount) == false ||\n  resource.config.gceClusterConfig.serviceAccount.contains('-compute@developer.gserviceaccount.com')"
      action_type    = "DENY"
      display_name   = "Disable Dataproc cluster with default service accounts"
      description    = "Enforce that the Dataproc VMs is not using default user-managed service accounts"
    }

    "custom.dataprocRequireDiskCmekEncryptionV4" = {
      resource_types = ["dataproc.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "has(resource.config.encryptionConfig.gcePdKmsKeyName) == false"
      action_type    = "DENY"
      display_name   = "Enable Dataproc CMEK encryption"
      description    = "Enforce that the Dataproc cluster is created with an CMEK encryption key."
    }

    "custom.dataprocRequireInternalIpV4" = {
      resource_types = ["dataproc.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.config.gceClusterConfig.internalIpOnly == false"
      action_type    = "DENY"
      display_name   = "Require Dataproc with internal IPs"
      description    = "Enforce that the Dataproc cluster is created with Internal IPs only"
    }

    "custom.dataprocRequireKerberosV4" = {
      resource_types = ["dataproc.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.config.securityConfig.kerberosConfig.enableKerberos == false"
      action_type    = "DENY"
      display_name   = "Require Dataproc with Kerberos authentication"
      description    = "Enforce that Dataproc cluster is configured using secure mode via Kerberos for authentication"
    }

    "custom.dnsAllowedSigningAlgorithmsV4" = {
      resource_types = ["dns.googleapis.com/ManagedZone"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.visibility == 'PUBLIC' &&\nresource.dnssecConfig.state == 'ON' &&\nresource.dnssecConfig.defaultKeySpecs.exists(spec,\n  spec.algorithm in [\"ECDSAP256SHA256\"] == false\n)"
      action_type    = "DENY"
      display_name   = "Require Cloud DNS DNSSEC configured to use only allowed algorithms in Cloud DNS DNSSEC"
      description    = "Ensure that allowed signing algorithms are used for the Key-Signing key and Zone-Signing key in Cloud DNS DNSSEC"
    }

    "custom.dnsRequireManageZoneDNSSECV4" = {
      resource_types = ["dns.googleapis.com/ManagedZone"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.visibility == \"PUBLIC\" && (resource.dnssecConfig.state in [\"ON\", \"TRANSFER\"] == false)"
      action_type    = "DENY"
      display_name   = "Require Cloud DNS DNSSEC enabled when configuring a DNS Public Managed Zone"
      description    = "Ensure that Cloud DNS DNSSEC is enabled when configuring a DNS Public Managed Zone"
    }

    "custom.dnsRequirePolicyLoggingV4" = {
      resource_types = ["dns.googleapis.com/Policy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.enableLogging != true"
      action_type    = "DENY"
      display_name   = "Require Cloud DNS logging enabled when configuring a DNS Policy"
      description    = "Ensure that Cloud DNS logging is enabled when configuring a DNS Policy"
    }

    "custom.firewallEnforcePolicyRuleLoggingV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule, rule.action != 'goto_next' && rule.enableLogging == false)"
      action_type    = "DENY"
      display_name   = "Require Firewall Policy rules to have logging enabled"
      description    = "Ensure that Firewall Policy rules have logging enabled"
    }

    "custom.firewallEnforceRuleLoggingV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "(\n  (has(resource.logConfig) == false || resource.logConfig.enable == false) &&\n  !resource.name.startsWith(\"gke-\") &&\n  !resource.name.startsWith(\"k8s-\") &&\n  !resource.name.endsWith(\"-hc\") &&\n  !resource.name.startsWith(\"k8s2-\") &&\n  !resource.name.startsWith(\"gkegw1-l7-\") &&\n  !resource.name.startsWith(\"gkemcg1-l7-\")\n)"
      action_type    = "DENY"
      display_name   = "Require VPC Firewall rules to have logging enabled"
      description    = "Ensure that VPC Firewall rules have logging enabled"
    }

    "custom.firewallRequireDescriptionV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE"]
      condition      = "(\n  resource.description == \"\" &&\n  !resource.name.startsWith(\"gke-\") &&\n  !resource.name.startsWith(\"k8s-\") &&\n  !resource.name.endsWith(\"-hc\") &&\n  !resource.name.startsWith(\"k8s2-\") &&\n  !resource.name.startsWith(\"gkegw1-l7-\") &&\n  !resource.name.startsWith(\"gkemcg1-l7-\")\n)"
      action_type    = "DENY"
      display_name   = "Require description on Firewall rule"
      description    = "Prevent the creation of VPC firewall rule that does not have description provided. Description can be used for auditing to refer to security control"
    }

    "custom.firewallRestrictCacheSearchDatabasesPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(r, r.priority < 2147483644 && r.direction == 'INGRESS' &&\n  r.match.srcIpRanges.exists(r, r == '0.0.0.0/0') &&\n  (\n    r.match.layer4Configs.containsIpProtocolAndPort('tcp', '6379') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('udp', '6379') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('tcp', '9200') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('udp', '9200') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('tcp', '9300') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('udp', '9300') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('tcp', '11211') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('udp', '11211') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('tcp', '11214') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('udp', '11214') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('tcp', '11215') ||\n    r.match.layer4Configs.containsIpProtocolAndPort('udp', '11215')\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing cache/search database port access from any source"
      description    = "Ensure that cache and search database ports (Elasticsearch, Memcached, Redis) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictCacheSearchDatabasesRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    resource.allowed.containsFirewallPort('tcp', '9200') ||\n    resource.allowed.containsFirewallPort('tcp', '9300') ||\n    resource.allowed.containsFirewallPort('tcp', '11211') ||\n    resource.allowed.containsFirewallPort('tcp', '11214') ||\n    resource.allowed.containsFirewallPort('tcp', '11215') ||\n    resource.allowed.containsFirewallPort('tcp', '6379') ||\n    resource.allowed.containsFirewallPort('udp', '11211') ||\n    resource.allowed.containsFirewallPort('udp', '11214') ||\n    resource.allowed.containsFirewallPort('udp', '11215')\n  )"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing cache/search database port access from any source"
      description    = "Ensure that cache and search database ports (Elasticsearch, Memcached, Redis) are not accessible from any source when using VPC Firewall Rule."
    }

    "custom.firewallRestrictDirectoryServicesPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '445') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '389') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '445') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '389') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '636')\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing directory service access from any source"
      description    = "Ensure that directory and authentication services (SMB/CIFS, LDAP) are not accessible from the Internet when using Firewall Policy Rule"
    }

    "custom.firewallRestrictDirectoryServicesRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    resource.allowed.containsFirewallPort('tcp', '445') ||\n    resource.allowed.containsFirewallPort('tcp', '389') ||\n    resource.allowed.containsFirewallPort('tcp', '636') ||\n    resource.allowed.containsFirewallPort('udp', '445') ||\n    resource.allowed.containsFirewallPort('udp', '389')\n  )"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing directory service access from any source"
      description    = "Ensure that directory and authentication services (SMB/CIFS, LDAP) are not accessible from the Internet when using VPC Firewall Rule"
    }

    "custom.firewallRestrictExplicitAllPortsPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.action == 'allow' &&\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.layer4Configs.exists(l4,\n    l4.ipProtocol in ['tcp', 'udp'] && (\n      !has(l4.ports) ||\n      '0-65535' in l4.ports ||\n      '1-65535' in l4.ports\n    )\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules with explicit all-ports specifications"
      description    = "Prevent Firewall Policy rules that explicitly specify all TCP/UDP ports using ranges like 0-65535 or 1-65535"
    }

    "custom.firewallRestrictExplicitAllPortsRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction == 'INGRESS' &&\nresource.allowed.exists(rule,\n  rule.IPProtocol in ['tcp', 'udp'] && (\n    !has(rule.ports) ||\n    '0-65535' in rule.ports ||\n    '1-65535' in rule.ports\n  )\n) &&\n!resource.name.startsWith('gke-') &&\n!resource.name.startsWith('k8s-') &&\n!resource.name.endsWith('-hc') &&\n!resource.name.startsWith('k8s2-') &&\n!resource.name.startsWith('gkegw1-l7-') &&\n!resource.name.startsWith('gkemcg1-l7-')"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules with explicit all-ports specifications"
      description    = "Prevent VPC firewall rules that explicitly specify all TCP/UDP ports using ranges like 0-65535 or 1-65535"
    }

    "custom.firewallRestrictInsecureProtocolsPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '21') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '23') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '80')\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing insecure protocol access from any source"
      description    = "Ensure that insecure legacy protocols (Telnet, FTP, HTTP) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictInsecureProtocolsRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    resource.allowed.containsFirewallPort('tcp', '21') ||\n    resource.allowed.containsFirewallPort('tcp', '23') ||\n    resource.allowed.containsFirewallPort('tcp', '80')\n  )"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing insecure protocol access from any source"
      description    = "Ensure that insecure legacy protocols (Telnet, FTP, HTTP) are not accessible from any source when using VPC Firewall Rule"
    }

    "custom.firewallRestrictMailProtocolsPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '25') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '110')\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing mail protocol access from any source"
      description    = "Ensure that mail protocols (SMTP, POP3) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictMailProtocolsRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    resource.allowed.containsFirewallPort('tcp', '25') ||\n    resource.allowed.containsFirewallPort('tcp', '110')\n  )"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing mail protocol access from any source"
      description    = "Ensure that mail protocols (SMTP, POP3) are not accessible from any source when using VPC Firewall Rule"
    }

    "custom.firewallRestrictManagementPortsPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '9090')\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing management port access from any source"
      description    = "Ensure that management interfaces (Cisco Secure WebSM) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictManagementPortsRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  resource.allowed.containsFirewallPort('tcp', '9090')"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing management port access from any source"
      description    = "Ensure that management interfaces (Cisco Secure WebSM) are not accessible from any source when using VPC Firewall Rule"
    }

    "custom.firewallRestrictNetworkServicesPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '53') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '53') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '137') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '137') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '138') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '138') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '139') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '139')\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing network service access from any source"
      description    = "Ensure that network infrastructure services (DNS, NetBIOS) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictNetworkServicesRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    resource.allowed.containsFirewallPort('tcp', '53') ||\n    resource.allowed.containsFirewallPort('udp', '53') ||\n    resource.allowed.containsFirewallPort('tcp', '137') ||\n    resource.allowed.containsFirewallPort('udp', '137') ||\n    resource.allowed.containsFirewallPort('tcp', '138') ||\n    resource.allowed.containsFirewallPort('udp', '138') ||\n    resource.allowed.containsFirewallPort('tcp', '139') ||\n    resource.allowed.containsFirewallPort('udp', '139')\n  )"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing network service access from any source"
      description    = "Ensure that network infrastructure services (DNS, NetBIOS) are not accessible from any source when using VPC Firewall Rule"
    }

    "custom.firewallRestrictNoSQLDatabasesPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '7000') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '7001') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '7199') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '8888') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '9042') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '9160') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '61620') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '61621') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '27017') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '27018') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '27019')\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing NoSQL database port access from any source"
      description    = "Ensure that NoSQL database ports (Cassandra, MongoDB) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictNoSQLDatabasesRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    resource.allowed.containsFirewallPort('tcp', '7000') ||\n    resource.allowed.containsFirewallPort('tcp', '7001') ||\n    resource.allowed.containsFirewallPort('tcp', '7199') ||\n    resource.allowed.containsFirewallPort('tcp', '8888') ||\n    resource.allowed.containsFirewallPort('tcp', '9042') ||\n    resource.allowed.containsFirewallPort('tcp', '9160') ||\n    resource.allowed.containsFirewallPort('tcp', '61620') ||\n    resource.allowed.containsFirewallPort('tcp', '61621') ||\n    resource.allowed.containsFirewallPort('tcp', '27017') ||\n    resource.allowed.containsFirewallPort('tcp', '27018') ||\n    resource.allowed.containsFirewallPort('tcp', '27019')\n  )"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing NoSQL database port access from any source"
      description    = "Ensure that NoSQL database ports (Cassandra, MongoDB) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictPublicAccessPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.action == 'allow' &&\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  !rule.match.layer4Configs.exists(l4,\n    l4.ipProtocol == 'icmp'\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy ingress rules allowing public Internet access"
      description    = "Prevent Firewall Policy ingress rules from 0.0.0.0/0 except for allowed protocols (ICMP)"
    }

    "custom.firewallRestrictPublicAccessRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction == 'INGRESS' &&\nsize(resource.allowed) > 0 &&\nresource.sourceRanges.exists(r, r == '0.0.0.0/0') &&\n!resource.allowed.exists(a,\n  a.IPProtocol == 'icmp'\n)"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall ingress rules allowing public Internet access"
      description    = "Prevent VPC Firewall ingress rules from 0.0.0.0/0 except for allowed protocols (ICMP)."
    }

    "custom.firewallRestrictRdpPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n    rule.priority < 2147483644 &&\n    rule.direction == 'INGRESS' &&\n    !rule.match.srcIpRanges.all(ipRange,\n        ipRange == '35.235.240.0/20' ||\n        ipRange.startsWith('192.168.') ||\n        ipRange.matches('^172\\.(?:1[6-9]|2\\d|3[0-1]).*') ||\n        ipRange.startsWith('10.')\n    ) &&\n    rule.match.layer4Configs.all(l4config,\n        l4config.ipProtocol == 'tcp' &&\n        l4config.ports.all(port, port == '3389')\n    )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing RDP access from any source"
      description    = "Ensure that RDP access is restricted from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictRdpRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n!resource.name.startsWith('gke-') &&\n!resource.name.startsWith('k8s-') &&\n!resource.name.endsWith('-hc') &&\n!resource.name.startsWith('k8s2-') &&\n!resource.name.startsWith('gkegw1-l7-') &&\n!resource.name.startsWith('gkemcg1-l7-') &&\nresource.allowed.containsFirewallPort('tcp', '3389') &&\n!resource.sourceRanges.all(range,\n  range == '35.235.240.0/20' ||\n  range.startsWith('10.') ||\n  range.matches('^172\\.(?:1[6-9]|2\\d|3[0-1]).*') ||\n  range.startsWith('192.168.')\n)"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing RDP access from any source"
      description    = "Ensure that RDP access is restricted from any source when using VPC Firewall Rule"
    }

    "custom.firewallRestrictSQLDatabasesPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n  rule.priority < 2147483644 &&\n  rule.direction == 'INGRESS' &&\n  rule.match.srcIpRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '3306') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '1521') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '2483') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '2484') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('tcp', '5432') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '2483') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '2484') ||\n    rule.match.layer4Configs.containsIpProtocolAndPort('udp', '5432')\n  )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing SQL database port access from any source"
      description    = "Ensure that SQL database ports (MySQL, Oracle, PostgreSQL) are not accessible from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictSQLDatabasesRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n  resource.sourceRanges.exists(range, range == '0.0.0.0/0') &&\n  (\n    resource.allowed.containsFirewallPort('tcp', '3306') ||\n    resource.allowed.containsFirewallPort('tcp', '1521') ||\n    resource.allowed.containsFirewallPort('tcp', '2483') ||\n    resource.allowed.containsFirewallPort('tcp', '2484') ||\n    resource.allowed.containsFirewallPort('tcp', '5432') ||\n    resource.allowed.containsFirewallPort('udp', '2483') ||\n    resource.allowed.containsFirewallPort('udp', '2484') ||\n    resource.allowed.containsFirewallPort('udp', '5432')\n  )"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing SQL database port access from any source"
      description    = "Ensure that SQL database ports (MySQL, Oracle, PostgreSQL) are not accessible from any source when using VPC Firewall Rule"
    }

    "custom.firewallRestrictSshPolicyRuleV4" = {
      resource_types = ["compute.googleapis.com/FirewallPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.rules.exists(rule,\n    rule.priority < 2147483644 &&\n    rule.direction == 'INGRESS' &&\n    !rule.match.srcIpRanges.all(ipRange,\n        ipRange == '35.235.240.0/20' ||\n        ipRange.startsWith('192.168.') ||\n        ipRange.matches('^172\\.(?:1[6-9]|2\\d|3[0-1]).*') ||\n        ipRange.startsWith('10.')\n    ) &&\n    rule.match.layer4Configs.all(l4config,\n        l4config.ipProtocol == 'tcp' &&\n        l4config.ports.all(port, port == '22')\n    )\n)"
      action_type    = "DENY"
      display_name   = "Restrict Firewall Policy rules allowing SSH access from any source"
      description    = "Ensure that SSH access is restricted from any source when using Firewall Policy Rule"
    }

    "custom.firewallRestrictSshRuleV4" = {
      resource_types = ["compute.googleapis.com/Firewall"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.direction.matches('INGRESS') &&\n!resource.name.startsWith('gke-') &&\n!resource.name.startsWith('k8s-') &&\n!resource.name.endsWith('-hc') &&\n!resource.name.startsWith('k8s2-') &&\n!resource.name.startsWith('gkegw1-l7-') &&\n!resource.name.startsWith('gkemcg1-l7-') &&\nresource.allowed.containsFirewallPort('tcp', '22') &&\n!resource.sourceRanges.all(range,\n  range == '35.235.240.0/20' ||\n  range.startsWith('10.') ||\n  range.matches('^172\\.(?:1[6-9]|2\\d|3[0-1]).*') ||\n  range.startsWith('192.168.')\n)"
      action_type    = "DENY"
      display_name   = "Restrict VPC Firewall rules allowing SSH access from any source"
      description    = "Ensure that SSH access is restricted from any source when using VPC Firewall Rule"
    }

    "custom.gkeAllowedNodePoolImagesV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.config.imageType in [\"COS_CONTAINERD\"] == false"
      action_type    = "DENY"
      display_name   = "Allow only authorized node pool images"
      description    = "Enforce that GKE nodes are using authorized node images"
    }

    "custom.gkeAllowedReleaseChannelsV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.releaseChannel.channel in [\"REGULAR\", \"STABLE\"] == false"
      action_type    = "DENY"
      display_name   = "Allow only authorized release channels"
      description    = "Enforce that GKE cluster are using authorized release channels"
    }

    "custom.gkeDisableAlphaClusterV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.enableKubernetesAlpha == true"
      action_type    = "DENY"
      display_name   = "Disable alpha features for production workloads"
      description    = "Enforce that GKE clusters are not using alpha features for production workloads"
    }

    "custom.gkeDisableKubernetesDashboardV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.addonsConfig.kubernetesDashboard.disabled == false"
      action_type    = "DENY"
      display_name   = "Disable Web UI dashboard"
      description    = "Enforce that GKE clusters does not have Web UI dashboard enabled"
    }

    "custom.gkeDisableLegacyAbacV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.legacyAbac.enabled == true"
      action_type    = "DENY"
      display_name   = "Disable legacy ABAC"
      description    = "Enforce that GKE clusters is configured with no legacy ABAC enabled"
    }

    "custom.gkeDisableLegacyMetadataEndpointsV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "('disable-legacy-endpoints' in resource.config.metadata &&\nresource.config.metadata['disable-legacy-endpoints'] == 'false')"
      action_type    = "DENY"
      display_name   = "Disable legacy metadata endpoints"
      description    = "Enforce that GKE clusters are created with legacy metadata endpoints disabled"
    }

    "custom.gkeRequireConfidentialNodesV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.confidentialNodes.enabled == false"
      action_type    = "DENY"
      display_name   = "Require confidential nodes"
      description    = "Enforce that the GKE clusters is using confidential nodes"
    }

    "custom.gkeRequireCOSImageV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.config.imageType != \"COS_CONTAINERD\""
      action_type    = "DENY"
      display_name   = "Require Container-Optimized OS on node pools"
      description    = "Enforce the nodes pool are using Container-Optimized OS for running containers"
    }

    "custom.gkeRequireDataplaneV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.networkConfig.datapathProvider != 'ADVANCED_DATAPATH'"
      action_type    = "DENY"
      display_name   = "Require dataplane v2"
      description    = "Enforce that the GKE clusters is configured to use dataplane v2"
    }

    "custom.gkeRequireGKEMetadataServerV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.config.workloadMetadataConfig.mode != 'GKE_METADATA'"
      action_type    = "DENY"
      display_name   = "Require GKE metadata server"
      description    = "Enforce that GKE clusters are configured with GKE metadata server enabled"
    }

    "custom.gkeRequireIntegrityMonitoringV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.config.shieldedInstanceConfig.enableIntegrityMonitoring == false"
      action_type    = "DENY"
      display_name   = "Enable integrity monitoring"
      description    = "Enforce that GKE nodes are configured with integrity monitoring enabled"
    }

    "custom.gkeRequireIntraNodeVisibilityV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.networkConfig.enableIntraNodeVisibility == false"
      action_type    = "DENY"
      display_name   = "Enable intranode visibility"
      description    = "Enforce that GKE clusters intranode visibility is enabled"
    }

    "custom.gkeRequireMasterAuthorizedNetworksV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.masterAuthorizedNetworksConfig.enabled == false"
      action_type    = "DENY"
      display_name   = "Require master authorized network with authorized CIDR IP ranges"
      description    = "Enforce that GKE clusters restrict network access to the control planes by configuring master authorized networks with authorized CIDR IP ranges"
    }

    "custom.gkeRequireMonitoringV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.monitoringService != 'monitoring.googleapis.com/kubernetes'"
      action_type    = "DENY"
      display_name   = "Enable monitoring"
      description    = "Enforce that GKE clusters monitoring is enabled"
    }

    "custom.gkeRequireNodePoolAutoRepairV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.management.autoRepair == false"
      action_type    = "DENY"
      display_name   = "Enable node auto-repair"
      description    = "Enforce that GKE clusters are configured with node auto-repair enabled"
    }

    "custom.gkeRequireNodePoolAutoUpgradeV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.management.autoUpgrade == false"
      action_type    = "DENY"
      display_name   = "Enable node auto-upgrade"
      description    = "Enforce that GKE clusters are configured with node auto-upgrade enabled"
    }

    "custom.gkeRequireNodePoolCMEKEncryptionV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "has(resource.config.bootDiskKmsKey) == false"
      action_type    = "DENY"
      display_name   = "Require NodePool CMEK Encryption"
      description    = "Enforce that GKE nodes are configured with CMEK Encryption"
    }

    "custom.gkeRequireNodePoolSandboxV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.name.matches(\"default-pool\") == false &&\n  has(resource.config.sandboxConfig) == false &&\n  resource.config.sandboxConfig.type != 'GVISOR'"
      action_type    = "DENY"
      display_name   = "Require GKE Sandbox runtime"
      description    = "Enforce that the GKE clusters nodes are isolated using GKE sandbox (excepting the default node pool)"
    }

    "custom.gkeRequirePrivateEndpointV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.privateClusterConfig.enablePrivateEndpoint == false"
      action_type    = "DENY"
      display_name   = "Disable public endpoints"
      description    = "Enforce that GKE clusters are created as private clusters with public endpoint disabled"
    }

    "custom.gkeRequireRegionalClustersV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.location.matches(\"^[a-z]+(-[a-z, 1-9]+)$\") == false"
      action_type    = "DENY"
      display_name   = "Require regional GKE cluster"
      description    = "Enforce the creation of regional GKE clusters"
    }

    "custom.gkeRequireSecureBootV4" = {
      resource_types = ["container.googleapis.com/NodePool"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.config.shieldedInstanceConfig.enableSecureBoot == false"
      action_type    = "DENY"
      display_name   = "Enable secure boot"
      description    = "Enforce that GKE nodes are configured with secure boot enabled"
    }

    "custom.gkeRequireVPCNativeClusterV4" = {
      resource_types = ["container.googleapis.com/Cluster"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.ipAllocationPolicy.useIpAliases == false"
      action_type    = "DENY"
      display_name   = "Require VPC-native"
      description    = "Enforce that GKE clusters are created with VPC-native"
    }

    "custom.iamAllowedMembersV4" = {
      resource_types = ["iam.googleapis.com/AllowPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.bindings.exists(binding,\n  binding.members.exists(member,\n    MemberSubjectStartsWith(member, ['user:', 'group:']) &&\n    !MemberSubjectEndsWith(member, ['@${var.org_domain}', '${var.admin_group_email}'])\n  )\n)"
      action_type    = "DENY"
      display_name   = "Deny principals and members outside the organization domain"
      description    = "Ensure no binding are done with members outside the organization domain"
    }

    "custom.iamDisableAdminServiceAccountV4" = {
      resource_types = ["iam.googleapis.com/AllowPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.bindings.exists(binding,\n  binding.members.exists(member,\n    !MemberSubjectEndsWith(member, ['@cloudservices.gserviceaccount.com']) &&\n    MemberSubjectStartsWith(member, ['serviceAccount:']) &&\n    !MemberSubjectEndsWith(member, ['@${var.iac_project_id}.iam.gserviceaccount.com'])\n  ) &&\n  (\n    RoleNameMatches(binding.role, ['roles/owner', 'roles/admin']) ||\n    RoleNameMatches(binding.role, ['roles/editor', 'roles/writer']) ||\n    RoleNameContains(binding.role, ['admin', 'Admin'])\n  )\n)"
      action_type    = "DENY"
      display_name   = "Deny use of the legacy basic roles, basic roles and usage of admin role for service account"
      description    = "Ensure no use of the legacy basic roles (owner and editor), basic roles (admin, writer) and usage of admin roles for service account"
    }

    "custom.iamDisableBasicRolesV4" = {
      resource_types = ["iam.googleapis.com/AllowPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.bindings.exists(binding,\n  binding.members.exists(member,\n    MemberSubjectStartsWith(member, ['user:', 'group:']) &&\n    !MemberSubjectStartsWith(member, ['${var.admin_group_email}']) &&\n    (\n      RoleNameMatches(binding.role, ['roles/owner', 'roles/admin']) ||\n      RoleNameMatches(binding.role, ['roles/editor', 'roles/writer']) ||\n      RoleNameContains(binding.role, ['roles/viewer', 'roles/reader'])\n    )\n  )\n)"
      action_type    = "DENY"
      display_name   = "Deny use of the basic roles"
      description    = "Ensure no use of the legacy basic roles (viewer, editor and owner) and basic roles (reader, writer and admin)"
    }

    "custom.iamDisableProjectServiceAccountImpersonationRolesV4" = {
      resource_types = ["iam.googleapis.com/AllowPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.bindings.exists(binding,\n  binding.members.exists(member,\n    MemberSubjectStartsWith(member, ['user:', 'group:']) &&\n    !MemberSubjectStartsWith(member, ['${var.admin_group_email}'])\n  ) &&\n  (\n    RoleNameMatches(binding.role, ['roles/iam.serviceAccountUser']) ||\n    RoleNameMatches(binding.role, ['roles/iam.serviceAccountTokenCreator'])\n  )\n)"
      action_type    = "DENY"
      display_name   = "Deny assignment of the service account user or service account token creator roles to users"
      description    = "Ensure that IAM Users are not assigned the service account user or service account token creator roles (requires usage of IAM Condition and tags to ensure the constraint is not applied on allowed service accounts)"
    }

    "custom.iamDisablePublicBindingsV4" = {
      resource_types = ["iam.googleapis.com/AllowPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.bindings.exists(binding,\n  binding.members.exists(member,\n    MemberSubjectMatches(member, ['allUsers', 'allAuthenticatedUsers'])\n  )\n)"
      action_type    = "DENY"
      display_name   = "Deny use of public access bindings with allUsers or allAuthenticatedUsers"
      description    = "Ensure no use of public bindings (allUsers, allAuthenticatedUsers)"
    }

    "custom.iamDisableRedisAdminRolesV4" = {
      resource_types = ["iam.googleapis.com/AllowPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.bindings.exists(binding,\n  binding.members.exists(member,\n    !MemberSubjectMatches(member, []) &&\n    (\n      RoleNameMatches(binding.role, ['roles/redis.admin']) ||\n      RoleNameMatches(binding.role, ['roles/redis.editor']) ||\n      RoleNameContains(binding.role, ['roles/redis.viewer'])\n    )\n  )\n)"
      action_type    = "DENY"
      display_name   = "Deny use of the basic roles"
      description    = "Ensure no use of the basic roles (viewer, editor and owner)"
    }

    "custom.networkDisableTargetHTTPProxyV4" = {
      resource_types = ["compute.googleapis.com/TargetHttpProxy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "true == true"
      action_type    = "DENY"
      display_name   = "Deny usage and creation of Target HTTP Proxy"
      description    = "Ensure Target HTTP Proxy are not used"
    }

    "custom.networkDisableWeakSSLPolicyV4" = {
      resource_types = ["compute.googleapis.com/SslPolicy"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "(resource.profile == \"COMPATIBLE\") || (resource.profile == \"CUSTOM\" &&\n  resource.customFeatures.exists(feature, feature in [\n  \"TLS_RSA_WITH_AES_128_GCM_SHA256\",\n  \"TLS_RSA_WITH_AES_256_GCM_SHA384\",\n  \"TLS_RSA_WITH_AES_128_CBC_SHA\",\n  \"TLS_RSA_WITH_AES_256_CBC_SHA\",\n  \"TLS_RSA_WITH_3DES_EDE_CBC_SHA\",\n  ])\n) || (resource.profile == \"CUSTOM\" &&\n  resource.minTlsVersion in [\"TLS_1_2\", \"TLS_1_3\"] == false\n) || (resource.profile == \"MODERN\" &&\n  resource.minTlsVersion in [\"TLS_1_2\", \"TLS_1_3\"] == false\n) || (resource.profile == \"RESTRICTED\" &&\n  resource.minTlsVersion in [\"TLS_1_2\", \"TLS_1_3\"] == false\n)"
      action_type    = "DENY"
      display_name   = "Deny usage of SSL Policies with weak cipher suites"
      description    = "Ensure SSL Policies created does not have weak cipher suites"
    }

    "custom.networkRequireBackendServiceLoggingV4" = {
      resource_types = ["compute.googleapis.com/BackendService"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "has(resource.logConfig) == false || resource.logConfig.enable == false"
      action_type    = "DENY"
      display_name   = "Require logging to be enabled on Backend Services"
      description    = "Enforce that Backend Services have logging enabled"
    }

    "custom.networkRequireCustomModeVpcV4" = {
      resource_types = ["compute.googleapis.com/Network"]
      method_types   = ["CREATE"]
      condition      = "resource.autoCreateSubnetworks == true"
      action_type    = "DENY"
      display_name   = "Require custom mode VPC network"
      description    = "Enforce that the subnets creation is using custom mode for a VPC network"
    }

    "custom.networkRequireSubnetPrivateGoogleAccessV4" = {
      resource_types = ["compute.googleapis.com/Subnetwork"]
      method_types   = ["CREATE"]
      condition      = "!resource.privateIpGoogleAccess && resource.purpose in ['REGIONAL_MANAGED_PROXY', 'GLOBAL_MANAGED_PROXY'] == false"
      action_type    = "DENY"
      display_name   = "Require Private Google Access"
      description    = "Enforce that the VPC network subnets are configured with private Google access"
    }

    "custom.storageRequireBucketObjectVersionningV4" = {
      resource_types = ["storage.googleapis.com/Bucket"]
      method_types   = ["CREATE", "UPDATE"]
      condition      = "resource.versioning.enabled == false"
      action_type    = "DENY"
      display_name   = "Require object versioning"
      description    = "Enforce Cloud Storage bucket object versioning to be configured"
    }
  }

  policies = {
    # ---------------------------------------------------------------------------
    # accesscontextmanager
    # ---------------------------------------------------------------------------
    "custom.accesscontextmanagerDisableBridgePerimetersV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # appengine
    # ---------------------------------------------------------------------------
    "appengine.disableCodeDownload" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # bigquery
    # ---------------------------------------------------------------------------
    "bigquery.disableBQOmniAWS" = {
      rules = [{ enforce = true }]
    }
    "bigquery.disableBQOmniAzure" = {
      rules = [{ enforce = true }]
    }
    "custom.iamDisablePublicBindingsV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # cloudbuild
    # ---------------------------------------------------------------------------
    "cloudbuild.allowedIntegrations" = {
      rules = [{ deny_all = true }]
    }
    "cloudbuild.allowedWorkerPools" = {
      rules = [{ values = { allow = ["under:organizations/${var.org_id}"] } }]
    }
    "cloudbuild.disableCreateDefaultServiceAccount" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudbuildDisableWorkerPoolExternalIPV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # cloudkms
    # ---------------------------------------------------------------------------
    "custom.cloudkmsAllowedAlgorithmsV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudkmsAllowedProtectionLevelV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudkmsAllowedRotationPeriodV4" = {
      rules = [{ enforce = true }]
    }
    "custom.dataprocRequireDiskCmekEncryptionV4" = {
      rules = [{ enforce = true }]
    }
    "gcp.restrictNonCmekServices" = {
      rules = [{
        values = {
          deny = [
            "aiplatform.googleapis.com",
            "alloydb.googleapis.com",
            "apigee.googleapis.com",
            "artifactregistry.googleapis.com",
            "bigquery.googleapis.com",
            "bigquerydatatransfer.googleapis.com",
            "bigtable.googleapis.com",
            "cloudfunctions.googleapis.com",
            "cloudtasks.googleapis.com",
            "composer.googleapis.com",
            "compute.googleapis.com",
            "contactcenterinsights.googleapis.com",
            "container.googleapis.com",
            "dataflow.googleapis.com",
            "dataform.googleapis.com",
            "datafusion.googleapis.com",
            "dataproc.googleapis.com",
            "dialogflow.googleapis.com",
            "discoveryengine.googleapis.com",
            "documentai.googleapis.com",
            "file.googleapis.com",
            "firestore.googleapis.com",
            "gkebackup.googleapis.com",
            "integrations.googleapis.com",
            "logging.googleapis.com",
            "looker.googleapis.com",
            "notebooks.googleapis.com",
            "pubsub.googleapis.com",
            "redis.googleapis.com",
            "run.googleapis.com",
            "secretmanager.googleapis.com",
            "securesourcemanager.googleapis.com",
            "spanner.googleapis.com",
            "speech.googleapis.com",
            "sqladmin.googleapis.com",
            "storage.googleapis.com",
            "storagetransfer.googleapis.com",
            "workstations.googleapis.com",
          ]
        }
      }]
    }

    # ---------------------------------------------------------------------------
    # compute
    # ---------------------------------------------------------------------------
    "compute.disableGuestAttributesAccess" = {
      rules = [{ enforce = true }]
    }
    "compute.disableInternetNetworkEndpointGroup" = {
      rules = [{ enforce = true }]
    }
    "compute.disableNestedVirtualization" = {
      rules = [{ enforce = true }]
    }
    "compute.disableSerialPortAccess" = {
      rules = [{ enforce = true }]
    }
    "compute.disableVpcExternalIpv6" = {
      rules = [{ enforce = true }]
    }
    "compute.managed.blockPreviewFeatures" = {
      rules = [{ enforce = true }]
    }
    "compute.managed.disableSerialPortLogging" = {
      rules = [{ enforce = true }]
    }
    "compute.managed.vmCanIpForward" = {
      rules = [{ enforce = true }]
    }
    "compute.requireOsLogin" = {
      rules = [{ enforce = true }]
    }
    "compute.requireShieldedVm" = {
      rules = [{ enforce = true }]
    }
    "compute.requireSslPolicy" = {
      rules = [{ values = { allow = ["under:organizations/${var.org_id}"] } }]
    }
    "compute.restrictLoadBalancerCreationForTypes" = {
      rules = [{ values = { allow = ["in:INTERNAL"] } }]
    }
    "compute.restrictProtocolForwardingCreationForTypes" = {
      rules = [{ values = { allow = ["is:INTERNAL"] } }]
    }
    "compute.setNewProjectDefaultToZonalDNSOnly" = {
      rules = [{ enforce = true }]
    }
    "compute.skipDefaultNetworkCreation" = {
      rules = [{ enforce = true }]
    }
    "compute.trustedImageProjects" = {
      rules = [{
        values = {
          allow = [
            "is:projects/centos-cloud",
            "is:projects/cos-cloud",
            "is:projects/debian-cloud",
            "is:projects/fedora-cloud",
            "is:projects/fedora-coreos-cloud",
            "is:projects/opensuse-cloud",
            "is:projects/rhel-cloud",
            "is:projects/rhel-sap-cloud",
            "is:projects/rocky-linux-cloud",
            "is:projects/suse-cloud",
            "is:projects/suse-sap-cloud",
            "is:projects/ubuntu-os-cloud",
            "is:projects/ubuntu-os-pro-cloud",
            "is:projects/windows-cloud",
            "is:projects/windows-sql-cloud",
            "is:projects/confidential-vm-images",
            "is:projects/confidential-space-images",
            "is:projects/backupdr-images",
            "is:projects/deeplearning-platform-release",
            "is:projects/serverless-vpc-access-images",
            "is:projects/gke-node-images",
            "is:projects/gke-windows-node-images",
            "is:projects/ubuntu-os-gke-cloud",
          ]
        }
      }]
    }
    "compute.vmExternalIpAccess" = {
      rules = [{ deny_all = true }]
    }
    "custom.networkRequireSubnetPrivateGoogleAccessV4" = {
      rules = [{ enforce = true }]
    }
    "gcp.restrictTLSCipherSuites" = {
      rules = [{ values = { allow = ["in:NIST-800-52-recommended-ciphers"] } }]
    }
    "gcp.restrictTLSVersion" = {
      rules = [{ values = { deny = ["TLS_VERSION_1", "TLS_VERSION_1_1"] } }]
    }
    "iam.automaticIamGrantsForDefaultServiceAccounts" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # dataproc
    # ---------------------------------------------------------------------------
    "custom.dataprocDisableDefaultServiceAccountV4" = {
      rules = [{ enforce = true }]
    }
    "custom.dataprocRequireInternalIpV4" = {
      rules = [{ enforce = true }]
    }
    "custom.dataprocRequireKerberosV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # dns
    # ---------------------------------------------------------------------------
    "custom.dnsAllowedSigningAlgorithmsV4" = {
      rules = [{ enforce = true }]
    }
    "custom.dnsRequireManageZoneDNSSECV4" = {
      rules = [{ enforce = true }]
    }
    "custom.dnsRequirePolicyLoggingV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # essentialcontacts
    # ---------------------------------------------------------------------------
    "essentialcontacts.allowedContactDomains" = {
      rules = [
        {
          values = { allow = ["@${var.org_domain}"] }
          condition = {
            title      = "Restrict essential contacts domains"
            expression = "!resource.matchTag('${var.org_id}/org-policies', 'allowed-essential-contacts-domains-all')"
          }
        },
        {
          allow_all = true
          condition = {
            title      = "Allow essential contacts from any domain"
            expression = "resource.matchTag('${var.org_id}/org-policies', 'allowed-essential-contacts-domains-all')"
          }
        },
      ]
    }

    # ---------------------------------------------------------------------------
    # firewall
    # ---------------------------------------------------------------------------
    "custom.firewallEnforcePolicyRuleLoggingV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallEnforceRuleLoggingV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRequireDescriptionV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictCacheSearchDatabasesPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictCacheSearchDatabasesRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictDirectoryServicesPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictDirectoryServicesRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictExplicitAllPortsPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictExplicitAllPortsRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictInsecureProtocolsPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictInsecureProtocolsRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictMailProtocolsPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictMailProtocolsRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictManagementPortsPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictManagementPortsRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictNetworkServicesPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictNetworkServicesRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictNoSQLDatabasesPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictNoSQLDatabasesRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictPublicAccessPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictPublicAccessRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictRdpPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictRdpRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictSQLDatabasesPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictSQLDatabasesRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictSshPolicyRuleV4" = {
      rules = [{ enforce = true }]
    }
    "custom.firewallRestrictSshRuleV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # gke
    # ---------------------------------------------------------------------------
    "container.managed.disableABAC" = {
      rules = [{ enforce = true }]
    }
    "container.managed.disableInsecureKubeletReadOnlyPort" = {
      rules = [{ enforce = true }]
    }
    "container.managed.disableLegacyClientCertificateIssuance" = {
      rules = [{ enforce = true }]
    }
    "container.managed.disableRBACSystemBindings" = {
      rules = [{ enforce = true }]
    }
    "container.managed.disallowDefaultComputeServiceAccount" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableBinaryAuthorization" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableCloudLogging" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableGoogleGroupsRBAC" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableNetworkPolicy" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enablePrivateNodes" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableSecretsEncryption" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableSecurityBulletinNotifications" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableShieldedNodes" = {
      rules = [{ enforce = true }]
    }
    "container.managed.enableWorkloadIdentityFederation" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeAllowedNodePoolImagesV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeAllowedReleaseChannelsV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeDisableAlphaClusterV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeDisableKubernetesDashboardV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeDisableLegacyAbacV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeDisableLegacyMetadataEndpointsV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireCOSImageV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireDataplaneV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireGKEMetadataServerV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireIntegrityMonitoringV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireIntraNodeVisibilityV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireMasterAuthorizedNetworksV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireMonitoringV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireNodePoolAutoRepairV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireNodePoolAutoUpgradeV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireNodePoolCMEKEncryptionV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireNodePoolSandboxV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequirePrivateEndpointV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireRegionalClustersV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireSecureBootV4" = {
      rules = [{ enforce = true }]
    }
    "custom.gkeRequireVPCNativeClusterV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # iam
    # ---------------------------------------------------------------------------
    "custom.iamDisableAdminServiceAccountV4" = {
      rules = [{ enforce = false }]
    }
    "custom.iamDisableBasicRolesV4" = {
      rules = [{ enforce = true }]
    }
    "custom.iamDisableProjectServiceAccountImpersonationRolesV4" = {
      rules = [
        {
          enforce = false
          condition = {
            title      = "Allow service account impersonation for tagged users"
            expression = "resource.matchTag('${var.org_id}/org-policies', 'allowed-sa-impersonation')"
          }
        },
        { enforce = true },
      ]
    }
    "custom.iamDisableRedisAdminRolesV4" = {
      rules = [{ enforce = false }]
    }
    "iam.managed.allowedPolicyMembers" = {
      rules = [
        {
          enforce = false
          condition = {
            title      = "Allow any member domain"
            expression = "resource.matchTag('${var.org_id}/org-policies', 'allowed-policy-member-domains-all')"
          }
        },
        { enforce = true },
      ]
    }
    "iam.disableAuditLoggingExemption" = {
      rules = [{ enforce = true }]
    }
    "iam.disableServiceAccountKeyCreation" = {
      rules = [{ enforce = true }]
    }
    "iam.disableServiceAccountKeyUpload" = {
      rules = [{ enforce = true }]
    }
    "iam.managed.disableServiceAccountApiKeyCreation" = {
      rules = [{ enforce = true }]
    }
    "iam.managed.preventPrivilegedBasicRolesForDefaultServiceAccounts" = {
      rules = [{ enforce = true }]
    }
    "iam.serviceAccountKeyExposureResponse" = {
      rules = [{ values = { allow = ["is:DISABLE_KEY"] } }]
    }
    "iam.workloadIdentityPoolAwsAccounts" = {
      rules = [{ deny_all = true }]
    }
    "iam.workloadIdentityPoolProviders" = {
      rules = [{ deny_all = true }]
    }

    # ---------------------------------------------------------------------------
    # network
    # ---------------------------------------------------------------------------
    "compute.disableVpcInternalIpv6" = {
      rules = [{ enforce = true }]
    }
    "compute.requireVpcFlowLogs" = {
      rules = [{ values = { allow = ["ESSENTIAL", "LIGHT", "COMPREHENSIVE"] } }]
    }
    "compute.restrictVpcPeering" = {
      rules = [{ values = { allow = ["under:organizations/${var.org_id}"] } }]
    }
    "custom.networkDisableTargetHTTPProxyV4" = {
      rules = [{ enforce = true }]
    }
    "custom.networkDisableWeakSSLPolicyV4" = {
      rules = [{ enforce = true }]
    }
    "custom.networkRequireBackendServiceLoggingV4" = {
      rules = [{ enforce = true }]
    }
    "custom.networkRequireCustomModeVpcV4" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # serverless
    # ---------------------------------------------------------------------------
    "cloudfunctions.allowedIngressSettings" = {
      rules = [{ values = { allow = ["ALLOW_INTERNAL_AND_GCLB"] } }]
    }
    "cloudfunctions.allowedVpcConnectorEgressSettings" = {
      rules = [{ values = { allow = ["ALL_TRAFFIC"] } }]
    }
    "cloudfunctions.requireVPCConnector" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudrunDisableEnvironmentVariablePatternV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudrunJobDisableDefaultServiceAccountV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudrunJobRequireBinaryAuthorizationV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudrunServiceDisableDefaultServiceAccountV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudrunServiceRequireBinaryAuthorizationV4" = {
      rules = [{ enforce = true }]
    }
    "run.allowedBinaryAuthorizationPolicies" = {
      rules = [{ values = { allow = ["default"] } }]
    }
    "run.allowedIngress" = {
      rules = [{ values = { allow = ["is:internal-and-cloud-load-balancing"] } }]
    }
    "run.allowedVPCEgress" = {
      rules = [{ values = { allow = ["all-traffic"] } }]
    }
    "run.managed.requireInvokerIam" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # sql
    # ---------------------------------------------------------------------------
    "custom.cloudsqlDisablePublicAuthorizedNetworksV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlEnforcePasswordComplexityV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequireAutomatedBackupV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequireHighAvailabilityV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequireMySQLDatabaseFlagsV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequirePointInTimeRecoveryV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequirePostgreSQLDatabaseAdditionalFlagsV4" = {
      rules = [{ enforce = false }]
    }
    "custom.cloudsqlRequirePostgreSQLDatabaseFlagsV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequireRootPasswordV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequireSQLServerDatabaseFlagsV4" = {
      rules = [{ enforce = true }]
    }
    "custom.cloudsqlRequireSSLConnectionV4" = {
      rules = [{ enforce = true }]
    }
    "sql.restrictAuthorizedNetworks" = {
      rules = [{ enforce = true }]
    }
    "sql.restrictPublicIp" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # storage
    # ---------------------------------------------------------------------------
    "storage.publicAccessPrevention" = {
      rules = [{ enforce = true }]
    }
    "storage.restrictAuthTypes" = {
      rules = [{ values = { deny = ["in:ALL_HMAC_SIGNED_REQUESTS"] } }]
    }
    "storage.secureHttpTransport" = {
      rules = [{ enforce = true }]
    }
    "storage.uniformBucketLevelAccess" = {
      rules = [{ enforce = true }]
    }

    # ---------------------------------------------------------------------------
    # vertexai
    # ---------------------------------------------------------------------------
    "ainotebooks.disableFileDownloads" = {
      rules = [{ enforce = true }]
    }
    "ainotebooks.disableRootAccess" = {
      rules = [{ enforce = true }]
    }
    "ainotebooks.restrictPublicIp" = {
      rules = [{ enforce = true }]
    }
    "ainotebooks.restrictVpcNetworks" = {
      rules = [{ values = { allow = ["under:organizations/${var.org_id}"] } }]
    }
  }
}
