# advanced_audit_policy

#### Table of Contents

1. [Overview](#overview)
2. [Module Description](#module-description)
3. [Setup](#setup)
    * [Setup requirements](#setup-requirements)
    * [GUID Lookup Hash Generation](#guid-lookup-hash-generation)
    * [What advanced_audit_policy affects](#what-advanced_audit_policy-affects)
    * [Beginning with advanced_audit_policy](#beginning-with-advanced_audit_policy)
4. [Usage](#usage)
    * [Parameters](#parameters)
    * [Examples](#examples)
5. [Reference](#reference)
6. [Limitations](#limitations)
7. [Development](#development)

## Overview
This module sets and enforces the advanced auditing policies for windows.

## Module Description
This module uses `auditpol.exe` to configure the advanced auditing policies on Windows. In addition all policies that are managed this way are stored in the `audit.csv` file  so that the local group policy will not overwrite these settings every couple of hours.

## Setup

### Setup Requirements

This module requires:
- [puppetlabs-stdlib](https://github.com/puppetlabs/puppetlabs-stdlib) (version requirement: >= 4.6.0)

### GUID Lookup Hash Generation

The Ruby module: guid_lookup_hash_generation.rb

This Ruby script can be used to generate the $guid_lookup_hash within the config.pp file found under manifest. This hash is used to map the advanced audit GUID policies back to the proper advanced audit subcategory name.

### What advanced_audit_policy affects
- Advanced auditing policies.
- `C:\Windows\system32\GroupPolicy\Machine\Microsoft\Windows NT\Audit`; the file in which windows group policy stores these policies.

### Beginning with advanced_audit_policy
To start using advanced_audit_policy, include the defined type in your profile.
Then configure the policies you want to set.

Note: This module can also remove unmanaged audit policies within this file. When this is done, the default settings for this auditing policy will be set when te system reapplies its advanced security policies.

## Usage

### Parameters
The advanced_audit_policy defined type accepts the following parameters:

#### policy (required)
Type: `String`

Default: `$title`

Values: Any valid advanced auditing subcategory.

Description: This String contains the auditing policy that will be managed with this module. Refer to the list of settings below.

#### ensure (optional)
Type: 'Enum'

Default: `'present'`

Values: `'present'` or `'absent'`

Description: Defines whether this subsetting should be absent or present in the advanced audit settings configuration csv.

#### success (optional)
Type: `Enum`

Default: `'disable'`

Description: Enables or disables the audit settings on success.

#### failure (optional)
Type: `Enum`

Default: `'disable'`

Description: Enables or disables the audit settings on failure.

### Examples

#### Example: Setting  multiple auditing policies
```puppet
  advanced_audit_policy {'Audit Logoff':
    ensure  => 'present',
    success => 'disable',
    failure => 'enable',
  }

  advanced_audit_policy {'Audit Logon':
    ensure => 'absent',
  }

  advanced_audit_policy {'example':
    policy  => 'Audit File Share'
    success => 'enable',
    failure => 'enable',
  }
```

## Available Settings

This module can manages the following settings, future settings can be added to `config.pp`:

### Windows 2008 R2 and higher

- 'Audit Account Lockout'
- 'Audit Application Generated'
- 'Audit Application Group Management'
- 'Audit Audit Policy Change'
- 'Audit Authentication Policy Change'
- 'Audit Authorization Policy Change'
- 'Audit Certification Services'
- 'Audit Computer Account Management'
- 'Audit Credential Validation'
- 'Audit Detailed Directory Service Replication'
- 'Audit Detailed File Share'
- 'Audit Directory Service Access'
- 'Audit Directory Service Changes'
- 'Audit Directory Service Replication'
- 'Audit Distribution Group Management'
- 'Audit DPAPI Activity'
- 'Audit File Share'
- 'Audit File System'
- 'Audit Filtering Platform Connection'
- 'Audit Filtering Platform Packet Drop'
- 'Audit Filtering Platform Policy Change'
- 'Audit Handle Manipulation'
- 'Audit IPsec Driver'
- 'Audit IPsec Extended Mode'
- 'Audit IPsec Main Mode'
- 'Audit IPsec Quick Mode'
- 'Audit Kerberos Authentication Service'
- 'Audit Kerberos Service Ticket Operations'
- 'Audit Kernel Object'
- 'Audit Logoff'
- 'Audit Logon'
- 'Audit MPSSVC Rule-Level Policy Change'
- 'Audit Network Policy Server'
- 'Audit Non Sensitive Privilege Use'
- 'Audit Other Account Logon Events'
- 'Audit Other Account Management Events'
- 'Audit Other Logon/Logoff Events'
- 'Audit Other Object Access Events'
- 'Audit Other Policy Change Events'
- 'Audit Other Privilege Use Events'
- 'Audit Other System Events'
- 'Audit Process Creation'
- 'Audit Process Termination'
- 'Audit Registry'
- 'Audit RPC Events'
- 'Audit SAM'
- 'Audit Security Group Management'
- 'Audit Security State Change'
- 'Audit Security System Extension'
- 'Audit Sensitive Privilege Use'
- 'Audit Special Logon'
- 'Audit System Integrity'
- 'Audit User Account Management'

#### Windows 2012 R2 and higher

- 'Audit Central Access Policy Staging'
- 'Audit Removable Storage'
- 'Audit User / Device Claims'

#### Windows 2016 and higher

- 'Audit Group Membership'
- 'Audit Token Right Adjusted'
- 'Audit PNP Activity'


## Reference

### Defined Types

- advanced_audit_policy

### Provider

- auditpolicy

## Limitations
This is where you list OS compatibility, version compatibility, etc.

This module works on:

# Desktop OSes
* Windows 7
* Windows 8/8.1
* Windows 10
* Windows 11

# Server OSes
* Windows 2008/2008 R2
* Windows Server 2012/2012 R2
* Windows Server 2016
* Windows Server 2019
* Windows Server 2022

## Development
You can contribute by submitting issues, providing feedback and joining the discussions.

Go to: `https://github.com/radsec/puppet-advanced_audit_policy`

If you want to fix bugs, add new features etc:
- Fork it
- Create a feature branch ( git checkout -b my-new-feature )
- Apply your changes and update rspec tests
- Run rspec tests ( bundle exec rake spec )
- Commit your changes ( git commit -am 'Added some feature' )
- Push to the branch ( git push origin my-new-feature )
- Create new Pull Request

