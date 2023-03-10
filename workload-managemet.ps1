Function New-WorkloadSupervisor {
    Param (
        [Parameter(Mandatory=$True)]$TanzuvCenterServer,
        [Parameter(Mandatory=$True)]$TanzuvCenterServerUsername,
        [Parameter(Mandatory=$True)]$TanzuvCenterServerPassword,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)]$TanzuContentLibrary,
        [Parameter(Mandatory=$True)][ValidateSet("TINY","SMALL","MEDIUM","LARGE")][string]$ControlPlaneSize,
        [Parameter(Mandatory=$False)]$MgmtNetwork,
        [Parameter(Mandatory=$True)]$MgmtNetworkStartIP,
        [Parameter(Mandatory=$True)]$MgmtNetworkSubnet,
        [Parameter(Mandatory=$True)]$MgmtNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNS,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkDNSDomain,
        [Parameter(Mandatory=$True)][string[]]$MgmtNetworkNTP,
        [Parameter(Mandatory=$False)][string]$WorkloadNetworkLabel,
        [Parameter(Mandatory=$False)][string]$WorkloadNetwork,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkStartIP,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkIPCount,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkSubnet,
        [Parameter(Mandatory=$True)][string]$WorkloadNetworkGateway,
        [Parameter(Mandatory=$True)][string[]]$WorkloadNetworkDNS,
        [Parameter(Mandatory=$False)]$WorkloadNetworkServiceCIDR="10.96.0.0/24",
        [Parameter(Mandatory=$True)][string]$NSXALBIPAddress,
        [Parameter(Mandatory=$True)][string]$NSXALBUsername,
        [Parameter(Mandatory=$True)][string]$NSXALBPassword,
        [Parameter(Mandatory=$False)][string]$NSXALBPort,
        [Parameter(Mandatory=$True)][string]$NSXALBCertName,
        [Parameter(Mandatory=$False)][string]$LoadBalancerLabel,
        [Parameter(Mandatory=$True)]$StoragePolicyName,
        [Parameter(Mandatory=$False)]$LoginBanner,
        [Switch]$EnableDebug
    )

    # Retrieve TLS certificate from NSX ALB using basic auth

    # Assumes Basic Auth has been enabled per automation below
    $pair = "${NSXALBUsername}:${NSXALBPassword}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)

    $headers = @{
        "Authorization"="basic $base64";
        "Content-Type"="application/json";
        "Accept"="application/json";
        "x-avi-version"="20.1.4";
    }

    try {
        Write-host -ForegroundColor Green "Extracting TLS certificate from NSX ALB ${NSXALBIPAddress} ..."
        $certResult = ((Invoke-WebRequest -Uri https://${NSXALBIPAddress}/api/sslkeyandcertificate?include_name -Method GET -Headers $headers -SkipCertificateCheck).Content | ConvertFrom-Json).results | where {$_.name -eq $NSXALBCertName}
    } catch {
        Write-Host -ForegroundColor Red "Error in extracting TLS certificate"
        Write-Error "`n($_.Exception.Message)`n"
        break
    }

    $nsxAlbCert = $certResult.certificate.certificate
    if($nsxAlbCert -eq $null) {
        Write-Host -ForegroundColor Red "Unable to locate TLS certificate in NSX ALB named $NSXALBCertName"
        break
    }

    Write-host -ForegroundColor Green "Connecting to Tanzu vCenter Server to enable Workload Management ..."
    Connect-VIServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

    if( (Get-ContentLibrary -Name $TanzuContentLibrary).syncdate -eq $NULL ) {
        Write-host -ForegroundColor Green "TKG Content Library has not fully sync'ed, please try again later"
        Disconnect-VIServer * -Confirm:$false
        break
    } else {
        Connect-CisServer $TanzuvCenterServer -User $TanzuvCenterServerUsername -Password $TanzuvCenterServerPassword -WarningAction SilentlyContinue | Out-Null

        # Cluster Moref
        $clusterService = Get-CisService "com.vmware.vcenter.cluster"
        $clusterFilterSpec = $clusterService.help.list.filter.Create()
        $clusterFilterSpec.names = @("$ClusterName")
        $clusterMoRef = $clusterService.list($clusterFilterSpec).cluster.Value
        if ($clusterMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Cluster ${ClusterName}"
            break
        }

        # Management Network Moref
        $networkService = Get-CisService "com.vmware.vcenter.network"
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$MgmtNetwork")
        $mgmtNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($mgmtNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Management Network ${MgmtNetwork}"
            break
        }

        # Workload Network Moref
        $networkFilterSpec = $networkService.help.list.filter.Create()
        $networkFilterSpec.names = @("$WorkloadNetwork")
        $workloadNetworkMoRef = $networkService.list($networkFilterSpec).network.Value
        if ($workloadNetworkMoRef -eq $NULL) {
            Write-Host -ForegroundColor Red "Unable to find vSphere Workload Network ${WorkloadNetwork}"
            break
        }

        $storagePolicyService = Get-CisService "com.vmware.vcenter.storage.policies"
        $sps= $storagePolicyService.list()
        $pacificSP = ($sps | where {$_.name -eq $StoragePolicyName}).Policy.Value

        $nsmClusterService = Get-CisService "com.vmware.vcenter.namespace_management.clusters"
        $spec = $nsmClusterService.help.enable.spec.Create()

        $networkProvider = "VSPHERE_NETWORK"
        $spec.size_hint = $ControlPlaneSize
        $spec.network_provider = $networkProvider

        # Management Network
        $managementStartRangeSpec = $nsmClusterService.help.enable.spec.master_management_network.address_range.Create()
        $managementStartRangeSpec.starting_address = $MgmtNetworkStartIP
        $managementStartRangeSpec.address_count = 5
        $managementStartRangeSpec.subnet_mask = $MgmtNetworkSubnet
        $managementStartRangeSpec.gateway = $MgmtNetworkGateway

        $mgmtNetworkSpec = $nsmClusterService.help.enable.spec.master_management_network.Create()
        $mgmtNetworkSpec.mode = "STATICRANGE"
        $mgmtNetworkSpec.network =  $mgmtNetworkMoRef
        $mgmtNetworkSpec.address_range = $managementStartRangeSpec

        $spec.master_management_network = $mgmtNetworkSpec

        $spec.master_DNS = @($MgmtNetworkDNS)
        $spec.master_DNS_search_domains = @($MgmtNetworkDNSDomain)
        $spec.master_NTP_servers = @($MgmtNetworkNTP)

        # Workload Network
        $supervisorAddressRangeSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.vsphere_network.address_ranges.Element.Create()
        $supervisorAddressRangeSpec.address = $WorkloadNetworkStartIP
        $supervisorAddressRangeSpec.count = $WorkloadNetworkIPCount

        $vsphereNetworkSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.vsphere_network.Create()
        $vsphereNetworkSpec.portgroup = $workloadNetworkMoRef
        $vsphereNetworkSpec.gateway = $WorkloadNetworkGateway
        $vsphereNetworkSpec.subnet_mask = $WorkloadNetworkSubnet
        $vsphereNetworkSpec.address_ranges = @($supervisorAddressRangeSpec)

        $supervisorWorkloadNetworkSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.supervisor_primary_workload_network.Create()
        $supervisorWorkloadNetworkSpec.network = $WorkloadNetworkLabel
        $supervisorWorkloadNetworkSpec.vsphere_network = $vsphereNetworkSpec
        $supervisorWorkloadNetworkSpec.network_provider = $networkProvider

        $workloadNetworksSpec = $nsmClusterService.help.enable.spec.workload_networks_spec.Create()
        $workloadNetworksSpec.supervisor_primary_workload_network = $supervisorWorkloadNetworkSpec
        $spec.workload_networks_spec = $workloadNetworksSpec

        # Load Balancer
        $lbAddressRange = $nsmClusterService.help.enable.spec.load_balancer_config_spec.address_ranges.Element.Create()
        $lbAddressRange.address = "0.0.0.0"
        $lbAddressRange.count = "1"

        $nsxAlbServerSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.avi_config_create_spec.server.Create()
        $nsxAlbServerSpec.host = $NSXALBIPAddress
        $nsxAlbServerSpec.port = $NSXALBPort

        $nsxAlbSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.avi_config_create_spec.Create()
        $nsxAlbSpec.server = $nsxAlbServerSpec
        $nsxAlbSpec.username = $NSXALBUsername
        $nsxAlbSpec.password = [VMware.VimAutomation.Cis.Core.Types.V1.Secret]$NSXALBPassword
        $nsxAlbSpec.certificate_authority_chain = $nsxAlbCert

        $lbSpec = $nsmClusterService.help.enable.spec.load_balancer_config_spec.Create()
        $lbSpec.id = $LoadBalancerLabel
        $lbSpec.provider = "AVI"
        $lbSpec.avi_config_create_spec = $nsxAlbSpec
        $lbSpec.address_ranges = @($lbAddressRange)

        $spec.load_balancer_config_spec = $lbSpec
        $spec.default_kubernetes_service_content_library = (Get-ContentLibrary -Name $TanzuContentLibrary)[0].id
        $spec.worker_DNS = @($WorkloadNetworkDNS)

        $serviceCidrSpec = $nsmClusterService.help.enable.spec.service_cidr.Create()
        $serviceAddress,$servicePrefix = $WorkloadNetworkServiceCIDR.split("/")
        $serviceCidrSpec.address = $serviceAddress
        $serviceCidrSpec.prefix = $servicePrefix
        $spec.service_cidr = $serviceCidrSpec

        $spec.master_storage_policy = $pacificSP
        $spec.ephemeral_storage_policy = $pacificSP

        $imagePolicySpec = $nsmClusterService.help.enable.spec.image_storage.Create()
        $imagePolicySpec.storage_policy = $pacificSP
        $spec.image_storage = $imagePolicySpec

        $LoginBanner = "

        " + [char]::ConvertFromUtf32(0x1F973) + " vSphere with Tanzu NSX Advanced LB Cluster " + [char]::ConvertFromUtf32(0x1F973) + "

    "
        $spec.login_banner = $LoginBanner

        # Output JSON payload
        if($EnableDebug) {
            $spec | ConvertTo-Json -Depth 5
        }

        try {
            Write-host -ForegroundColor Green "Enabling Tanzu Workload Management on vSphere Cluster ${ClusterName} ..."
            $nsmClusterService.enable($clusterMoRef,$spec)
        } catch {
            Write-host -ForegroundColor red "Error in attempting to enable Tanzu Workload Management on vSphere Cluster ${ClusterName}"
            Write-host -ForegroundColor red "($_.Exception.Message)"
            Disconnect-VIServer * -Confirm:$false | Out-Null
            Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
            break
        }
        Write-host -ForegroundColor Green "Please refer to the Tanzu Workload Management UI in vCenter Server to monitor the progress of this operation"

        Write-host -ForegroundColor Green "Disconnecting from Tanzu Management vCenter ..."
        Disconnect-VIServer * -Confirm:$false | Out-Null
        Disconnect-CisServer $global:DefaultCisServers -Confirm:$false | Out-Null
    }
}


$vSphereWithTanzuParams = @{
    TanzuvCenterServer          = "vcenter.vsphere.local";
    TanzuvCenterServerUsername  = "administrator@vsphere.local";
    TanzuvCenterServerPassword  = "secret";
    ClusterName                 = "Cluster";
    TanzuContentLibrary         = "k8s-tkr";
    ControlPlaneSize            = "MEDIUM";
    MgmtNetwork                 = "MGMT-VLAN";
    MgmtNetworkStartIP          = "10.0.0.2";
    MgmtNetworkSubnet           = "255.255.255.0";
    MgmtNetworkGateway          = "10.0.0.1";
    MgmtNetworkDNS              = @("10.1.1.1","10.1.1.2");
    MgmtNetworkDNSDomain        = "vsphere.local";
    MgmtNetworkNTP              = @("10.1.1.1","10.1.1.2");
    WorkloadNetwork             = "PWWDL-VLAN";
    WorkloadNetworkLabel        = "k8s-pwld-vlan";    
    WorkloadNetworkStartIP      = "10.2.1.1";
    WorkloadNetworkIPCount      = 200;
    WorkloadNetworkSubnet       = "255.255.255.0";
    WorkloadNetworkGateway      = "10.2.1.1";
    WorkloadNetworkDNS          = @("10.1.1.1","10.1.1.2");
    WorkloadNetworkServiceCIDR  = "10.96.0.0/24";
    StoragePolicyName           = "custom-k8s-storage";
    NSXALBIPAddress             = "nsxalbctrlvip.vsphere.local";
    LoadBalancerLabel           = "nsx-alb"
    NSXALBPort                  = "443";
    NSXALBCertName              = "nsxalbctrlvip.vsphere.local-ssl"
    NSXALBUsername              = "admin";
    NSXALBPassword              = "secret";
}

New-WorkloadSupervisor @vSphereWithTanzuParams
