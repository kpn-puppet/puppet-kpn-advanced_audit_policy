# Define advanced_audit_policy
class advanced_audit_policy::config {

  $audit_csv_folder_path = 'GroupPolicy/Machine/Microsoft/Windows NT/Audit'
  $audit_csv_file_path   = "${facts['os']['windows']['system32']}/${audit_csv_folder_path}/audit.csv"

  # Make sure the CSV file exists and contains the proper header 
  $audit_csv_folder_path.split('/').reduce($facts['os']['windows']['system32']) |$memo, $value| {
    file { "${memo}/${value}":
      ensure => 'directory',
    }
    "${memo}/${value}"
  }

  # Ensure audit.csv exists and contains at least a header
  file {$audit_csv_file_path:
    ensure => 'file',
  }

  file_line { 'audit_csv_file_header':
    ensure => 'present',
    path   => $audit_csv_file_path,
    line   => 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value',
  }

  # Build Data for auditing policy CSV
  # This hash is used to find the GUID matching this audit setting
  # https://msdn.microsoft.com/en-us/library/windows/desktop/bb648638(v=vs.85).aspx
  $guid_lookup_hash = {
    'Audit Credential Validation'                  => '{0cce923f-69ae-11d9-bed3-505054503030}',
    'Audit Kerberos Authentication Service'        => '{0cce9242-69ae-11d9-bed3-505054503030}',
    'Audit Kerberos Service Ticket Operations'     => '{0cce9240-69ae-11d9-bed3-505054503030}',
    'Audit Other Account Logon Events'             => '{0cce9241-69ae-11d9-bed3-505054503030}',
    'Audit Application Group Management'           => '{0cce9239-69ae-11d9-bed3-505054503030}',
    'Audit Computer Account Management'            => '{0cce9236-69ae-11d9-bed3-505054503030}',
    'Audit Distribution Group Management'          => '{0cce9238-69ae-11d9-bed3-505054503030}',
    'Audit Other Account Management Events'        => '{0cce923a-69ae-11d9-bed3-505054503030}',
    'Audit Security Group Management'              => '{0cce9237-69ae-11d9-bed3-505054503030}',
    'Audit User Account Management'                => '{0cce9235-69ae-11d9-bed3-505054503030}',
    'Audit DPAPI Activity'                         => '{0cce922d-69ae-11d9-bed3-505054503030}',
    'Audit PNP Activity'                           => '{0cce9248-69ae-11d9-bed3-505054503030}', # Windows 2016 and higher
    'Audit Process Creation'                       => '{0cce922b-69ae-11d9-bed3-505054503030}',
    'Audit Process Termination'                    => '{0cce922c-69ae-11d9-bed3-505054503030}',
    'Audit RPC Events'                             => '{0cce922e-69ae-11d9-bed3-505054503030}',
    'Audit Token Right Adjusted'                   => '{0cce924a-69ae-11d9-bed3-505054503030}', # Windows 2016 and higher
    'Audit Detailed Directory Service Replication' => '{0cce923e-69ae-11d9-bed3-505054503030}',
    'Audit Directory Service Access'               => '{0cce923b-69ae-11d9-bed3-505054503030}',
    'Audit Directory Service Changes'              => '{0cce923c-69ae-11d9-bed3-505054503030}',
    'Audit Directory Service Replication'          => '{0cce923d-69ae-11d9-bed3-505054503030}',
    'Audit Account Lockout'                        => '{0cce9217-69ae-11d9-bed3-505054503030}',
    'Audit User / Device Claims'                   => '{0cce9247-69ae-11d9-bed3-505054503030}', # Windows 2012 R2 and higher
    'Audit Group Membership'                       => '{0cce9249-69ae-11d9-bed3-505054503030}', # Windows 2016 and higher
    'Audit IPsec Extended Mode'                    => '{0cce921a-69ae-11d9-bed3-505054503030}',
    'Audit IPsec Main Mode'                        => '{0cce9218-69ae-11d9-bed3-505054503030}',
    'Audit IPsec Quick Mode'                       => '{0cce9219-69ae-11d9-bed3-505054503030}',
    'Audit Logoff'                                 => '{0cce9216-69ae-11d9-bed3-505054503030}',
    'Audit Logon'                                  => '{0cce9215-69ae-11d9-bed3-505054503030}',
    'Audit Network Policy Server'                  => '{0cce9243-69ae-11d9-bed3-505054503030}',
    'Audit Other Logon/Logoff Events'              => '{0cce921c-69ae-11d9-bed3-505054503030}',
    'Audit Special Logon'                          => '{0cce921b-69ae-11d9-bed3-505054503030}',
    'Audit Application Generated'                  => '{0cce9222-69ae-11d9-bed3-505054503030}',
    'Audit Certification Services'                 => '{0cce9221-69ae-11d9-bed3-505054503030}',
    'Audit Detailed File Share'                    => '{0cce9244-69ae-11d9-bed3-505054503030}',
    'Audit File Share'                             => '{0cce9224-69ae-11d9-bed3-505054503030}',
    'Audit File System'                            => '{0cce921d-69ae-11d9-bed3-505054503030}',
    'Audit Filtering Platform Connection'          => '{0cce9226-69ae-11d9-bed3-505054503030}',
    'Audit Filtering Platform Packet Drop'         => '{0cce9225-69ae-11d9-bed3-505054503030}',
    'Audit Handle Manipulation'                    => '{0cce9223-69ae-11d9-bed3-505054503030}',
    'Audit Kernel Object'                          => '{0cce921f-69ae-11d9-bed3-505054503030}',
    'Audit Other Object Access Events'             => '{0cce9227-69ae-11d9-bed3-505054503030}',
    'Audit Registry'                               => '{0cce921e-69ae-11d9-bed3-505054503030}',
    'Audit Removable Storage'                      => '{0cce9245-69ae-11d9-bed3-505054503030}', # Windows 2012 R2 and higher
    'Audit SAM'                                    => '{0cce9220-69ae-11d9-bed3-505054503030}',
    'Audit Central Access Policy Staging'          => '{0cce9246-69ae-11d9-bed3-505054503030}', # Windows 2012 R2 and higher
    'Audit Audit Policy Change'                    => '{0cce922f-69ae-11d9-bed3-505054503030}',
    'Audit Authentication Policy Change'           => '{0cce9230-69ae-11d9-bed3-505054503030}',
    'Audit Authorization Policy Change'            => '{0cce9231-69ae-11d9-bed3-505054503030}',
    'Audit Filtering Platform Policy Change'       => '{0cce9233-69ae-11d9-bed3-505054503030}',
    'Audit MPSSVC Rule-Level Policy Change'        => '{0cce9232-69ae-11d9-bed3-505054503030}',
    'Audit Other Policy Change Events'             => '{0cce9234-69ae-11d9-bed3-505054503030}',
    'Audit Non Sensitive Privilege Use'            => '{0cce9229-69ae-11d9-bed3-505054503030}',
    'Audit Other Privilege Use Events'             => '{0cce922a-69ae-11d9-bed3-505054503030}',
    'Audit Sensitive Privilege Use'                => '{0cce9228-69ae-11d9-bed3-505054503030}',
    'Audit IPsec Driver'                           => '{0cce9213-69ae-11d9-bed3-505054503030}',
    'Audit Other System Events'                    => '{0cce9214-69ae-11d9-bed3-505054503030}',
    'Audit Security State Change'                  => '{0cce9210-69ae-11d9-bed3-505054503030}',
    'Audit Security System Extension'              => '{0cce9211-69ae-11d9-bed3-505054503030}',
    'Audit System Integrity'                       => '{0cce9212-69ae-11d9-bed3-505054503030}',
  }

}
