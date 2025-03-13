# frozen_string_literal: true

require 'spec_helper'

describe 'advanced_audit_policy' do
  on_supported_os.each do |os, facts|
    describe os do
      let(:facts) { facts }

      context 'with parameter validation' do
        describe 'policy is not a string' do
          let(:title) { 'Audit Logoff' }
          let(:params) { { 'policy' => 0 } }

          it { is_expected.to raise_error(Puppet::Error, %r{expects a String}) }
        end

        describe 'policy is unknown' do
          let(:title) { 'foo' }
          let(:params) { { 'policy' => 'bar' } }

          it { is_expected.to raise_error(Puppet::Error, %r{is not a known audit policy}) }
        end

        describe 'success has illegal value' do
          let(:title) { 'Audit Logon' }
          let(:params) { { 'success' => 'notInEnum' } }

          it { is_expected.to raise_error(Puppet::Error, %r{expects a match for Enum\['disable', 'enable'\]}) }
        end

        describe 'failure has illegal value' do
          let(:title) { 'Audit Logon' }
          let(:params) { { 'failure' => 'notInEnum' } }

          it { is_expected.to raise_error(Puppet::Error, %r{expects a match for Enum\['disable', 'enable'\]}) }
        end

        describe 'ensure has illegal value' do
          let(:title) { 'Audit Logon' }
          let(:params) { { 'ensure' => 'notInEnum' } }

          it { is_expected.to raise_error(Puppet::Error, %r{expects a match for Enum\['absent', 'present'\]}) }
        end

        describe 'valid input parameters' do
          let(:title) { 'Audit Logon' }
          let(:params) { {} }

          it { is_expected.to compile.with_all_deps }
        end
      end

      context 'with default params' do
        let(:title) { 'Audit Logon' }
        let(:params) { {} }

        it { is_expected.to contain_class('advanced_audit_policy::config') }
        it { is_expected.to contain_file('C:\Windows\system32/GroupPolicy').with('ensure' => 'directory') }
        it { is_expected.to contain_file('C:\Windows\system32/GroupPolicy/Machine').with('ensure' => 'directory') }
        it { is_expected.to contain_file('C:\Windows\system32/GroupPolicy/Machine/Microsoft').with('ensure' => 'directory') }
        it { is_expected.to contain_file('C:\Windows\system32/GroupPolicy/Machine/Microsoft/Windows NT').with('ensure' => 'directory') }
        it { is_expected.to contain_file('C:\Windows\system32/GroupPolicy/Machine/Microsoft/Windows NT/Audit').with('ensure' => 'directory') }
        it { is_expected.to contain_file('C:\Windows\system32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv').with('ensure' => 'file') }
        it { is_expected.to contain_file_line('audit_csv_file_header').with('ensure' => 'present') }
        it { is_expected.to contain_file_line('audit_csv_file_header').with('path' => 'C:\Windows\system32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') }
        it { is_expected.to contain_file_line('audit_csv_file_header').with('line' => 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value') }
        it { is_expected.to contain_audit_policy('Logon').with('success' => 'disable', 'failure' => 'disable') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9215-69ae-11d9-bed3-505054503030}').with('ensure' => 'present') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9215-69ae-11d9-bed3-505054503030}').with('path' => 'C:\Windows\system32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9215-69ae-11d9-bed3-505054503030}').with('line' => ',System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},No Auditing,,0') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9215-69ae-11d9-bed3-505054503030}').with('match' => '^,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},') }
      end

      context 'when configuring auditing policy, with naming exception' do
        let(:title) { 'auditing_policy' }
        let(:params) do
          {
            'policy' => 'Audit Central Access Policy Staging',
            'success' => 'enable',
            'failure' => 'disable',
          }
        end

        it { is_expected.to contain_audit_policy('Central Policy Staging').with('success' => 'enable') }
        it { is_expected.to contain_audit_policy('Central Policy Staging').with('failure' => 'disable') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9246-69ae-11d9-bed3-505054503030}').with('ensure' => 'present') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9246-69ae-11d9-bed3-505054503030}').with('path' => 'C:\Windows\system32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9246-69ae-11d9-bed3-505054503030}').with('line' => ',System,Audit Central Access Policy Staging,{0cce9246-69ae-11d9-bed3-505054503030},Success,,1') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9246-69ae-11d9-bed3-505054503030}').with('match' => '^,System,Audit Central Access Policy Staging,{0cce9246-69ae-11d9-bed3-505054503030},') }
      end

      context 'when ensuring an auditing policy is absent' do
        let(:title) { 'Audit Kerberos Authentication Service' }
        let(:params) { { 'ensure' => 'absent' } }

        it { is_expected.not_to contain_audit_policy('Kerberos Authentication Service') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9242-69ae-11d9-bed3-505054503030}').with('ensure' => 'absent') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9242-69ae-11d9-bed3-505054503030}').with('path' => 'C:\Windows\system32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv') }
        it { is_expected.to contain_file_line('audit_csv_line_{0cce9242-69ae-11d9-bed3-505054503030}').with('match' => '^,System,Audit Kerberos Authentication Service,{0cce9242-69ae-11d9-bed3-505054503030},') }
      end
    end
  end
end
