# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'advanced_audit_policy class', unless: UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do
  context 'with default parameters' do
    it 'will work idempotently with no errors' do
      pp = <<-AAP
      advanced_audit_policy { 'Audit Logoff':
        success => 'disable',
        failure => 'enable',
      }
      AAP

      # Run it twice and test for idempotency
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end

    describe command('auditpol /get /subcategory:Logoff /r') do
      its(:stdout) { is_expected.to match %r{,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Failure,} }
    end

    describe file('C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') do
      its(:content) { is_expected.to match %r{,System,Audit Logoff,{0cce9216-69ae-11d9-bed3-505054503030},Failure,,2} }
    end
  end

  context 'when removing the auditing policies set in the initial test' do
    it 'will work idempotently with no errors' do
      pp = <<-AAP
        advanced_audit_policy { 'Audit Logoff':
          ensure => 'absent',
        }
      AAP

      # Run it twice and test for idempotency
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end

    describe file('C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') do
      its(:content) { is_expected.not_to match %r{,System,Audit Logoff,{0cce9215-69ae-11d9-bed3-505054503030} } }
    end
  end

  context 'with a profile of advanced auditing policies' do
    it 'will work idempotently with no errors' do
      pp = <<-AAP
      advanced_audit_policy { 'test1':
        policy  => 'Audit Credential Validation',
        success => 'disable',
        failure => 'enable',
      }

      advanced_audit_policy { 'test2':
        policy  => 'Audit Application Group Management',
        success => 'enable',
        failure => 'disable',
      }

      advanced_audit_policy { 'test3':
        policy  => 'Audit Computer Account Management',
        success => 'enable',
        failure => 'enable',
      }

      advanced_audit_policy { 'test4':
        policy  => 'Audit Other Account Management Events',
        success => 'enable',
        failure => 'enable',
      }

      advanced_audit_policy { 'test5':
        policy  => 'Audit Security Group Management',
        success => 'enable',
        failure => 'enable',
      }

      if $::operatingsystemmajrelease != '2008 R2' {
        advanced_audit_policy { 'test6':
          policy  => 'Audit Central Access Policy Staging',
          success => 'disable',
          failure => 'disable',
        }
      }
      AAP
      # Run it twice and test for idempotency
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end

    describe command('auditpol /get /subcategory:"Credential Validation" /r') do
      its(:stdout) { is_expected.to match %r{,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Failure,} }
    end

    describe command('auditpol /get /subcategory:"Application Group Management" /r') do
      its(:stdout) { is_expected.to match %r{,System,Application Group Management,{0CCE9239-69AE-11D9-BED3-505054503030},Success,} }
    end

    describe command('auditpol /get /subcategory:"Computer Account Management" /r') do
      its(:stdout) { is_expected.to match %r{,System,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,} }
    end

    describe command('auditpol /get /subcategory:"Other Account Management Events" /r') do
      its(:stdout) { is_expected.to match %r{,System,Other Account Management Events,{0CCE923A-69AE-11D9-BED3-505054503030},Success and Failure,} }
    end

    describe command('auditpol /get /subcategory:"Security Group Management" /r') do
      its(:stdout) { is_expected.to match %r{,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,} }
    end

    if fact('operatingsystemmajrelease') != '2008 R2'
      describe command('auditpol /get /subcategory:"Central Policy Staging" /r') do
        its(:stdout) { is_expected.to match %r{,System,Central Policy Staging,{0CCE9246-69AE-11D9-BED3-505054503030},No Auditing,} }
      end
    end

    describe file('C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') do
      its(:content) { is_expected.to match %r{,System,Audit Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Failure,,2} }
      its(:content) { is_expected.to match %r{,System,Audit Application Group Management,{0cce9239-69ae-11d9-bed3-505054503030},Success,,1} }
      its(:content) { is_expected.to match %r{,System,Audit Computer Account Management,{0cce9236-69ae-11d9-bed3-505054503030},Success and Failure,,3} }
      its(:content) { is_expected.to match %r{,System,Audit Other Account Management Events,{0cce923a-69ae-11d9-bed3-505054503030},Success and Failure,,3} }
      its(:content) { is_expected.to match %r{,System,Audit Security Group Management,{0cce9237-69ae-11d9-bed3-505054503030},Success and Failure,,3} }
    end

    if fact('operatingsystemmajrelease') != '2008 R2'
      describe file('C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') do
        its(:content) { is_expected.to match %r{,System,Audit Central Access Policy Staging,{0cce9246-69ae-11d9-bed3-505054503030},No Auditing,,0} }
      end
    end

    # Now we restore our audit policies using this file to make sure it is syntactically sound.
    describe command('auditpol /restore /file:"C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv"') do
      its(:stdout) { is_expected.to match %r{The command was successfully executed.} }
    end
  end
end
