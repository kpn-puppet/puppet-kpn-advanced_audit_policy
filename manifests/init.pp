# Define advanced_audit_policies
#
# @param policy [String] The name of the audit policy to configure
# @param ensure [Enum['present', 'absent']] Whether the policy should be present or absent
# @param success [Enum['enable', 'disable']] Whether to enable auditing for successful events
# @param failure [Enum['enable', 'disable']] Whether to enable auditing for failed events
#
define advanced_audit_policy (
  String                    $policy  = $title,
  Enum['present', 'absent'] $ensure  = 'present',
  Enum['enable', 'disable'] $success = 'disable',
  Enum['enable', 'disable'] $failure = 'disable',
) {
  if "${facts['os']['name']} ${facts['os']['release']['major']}" !~ /(w|W)indows (2008( R2)?|2012( R2)?|2016|10|2019|2022)/ {
    fail("Module ${module_name} is not supported on ${facts['os']['name']} ${facts['os']['release']['major']}.")
  }

  # Make sure audit.csv exists and has a header
  include advanced_audit_policy::config

  $guid_lookup_hash    = $advanced_audit_policy::config::guid_lookup_hash
  $audit_csv_file_path = $advanced_audit_policy::config::audit_csv_file_path

  if !member($guid_lookup_hash.keys, $policy) {
    fail("'${policy}' is not a known audit policy, must be one of ${guid_lookup_hash.keys.join(', ')}")
  }

  # Some settings are named different in auditpol.csv/gpedit.msc vs auditpol.exe /category:* /r
  $auditpol_name = $policy ? {
    'Audit Central Access Policy Staging' => 'Central Policy Staging',
    'Audit Token Right Adjusted'          => 'Token Right Adjusted Events',
    'Audit PNP Activity'                  => 'Plug and Play Events',
    default                               => regsubst($policy, '^Audit\s', ''),
  }

  # Set actual auditing policies
  if $ensure == 'present' {
    # Activate the setting using auditpol.exe
    audit_policy { $auditpol_name:
      success => $success,
      failure => $failure,
    }
  }

  # Based on the "Success" and "Failure" values the setting name and value to be used in the CSV output will be set
  $setting_csv = "${success}_${failure}".downcase ? {
    'disable_disable' => ['0', 'No Auditing'],
    'enable_disable'  => ['1', 'Success'],
    'disable_enable'  => ['2', 'Failure'],
    'enable_enable'   => ['3', 'Success and Failure'],
  }

  $policy_guid = $guid_lookup_hash[$policy]

  file_line { "audit_csv_line_${policy_guid}":
    ensure            => $ensure,
    path              => $audit_csv_file_path,
    line              => ",System,${policy},${policy_guid},${setting_csv[1]},,${setting_csv[0]}",
    match             => "^,System,${policy},${policy_guid},",
    match_for_absence => true,
  }
}
