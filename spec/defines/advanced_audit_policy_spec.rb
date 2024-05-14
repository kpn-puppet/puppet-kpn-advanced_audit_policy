# frozen_string_literal: true

require 'spec_helper'

describe 'advanced_audit_policy' do
  context 'with unsupported operating system' do
    describe '(CentOS 6)' do
      let(:title) { 'Audit Logon' }
      let(:params) { { 'success' => 'disable', 'failure' => 'enable' } }
      let(:facts) do
        { os: { family: 'RedHat', release: { major: '6' } } }
      end

      it { is_expected.to raise_error(Puppet::Error, %r{is not supported}) }
    end
    describe '(Windows 2003 R2)' do
      let(:title) { 'Audit Logon' }
      let(:params) { { 'success' => 'disable', 'failure' => 'enable' } }
      let(:facts) do
        { os: { family: 'Windows', release: { major: '2003 R2' } } }
      end

      it { is_expected.to raise_error(Puppet::Error, %r{is not supported}) }
    end
  end

  context 'with supported operating system' do
    [
      { os: { family: 'windows', release: { major: '10' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '11' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '2008' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '2008 R2' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '2012' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '2012 R2' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '2016' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '2019' }, windows: { system32: 'C:/Windows/System32' } } },
      { os: { family: 'windows', release: { major: '2022' }, windows: { system32: 'C:/Windows/System32' } } },
    ].each do |facts|
      describe "for #{facts[:os][:family]} #{facts[:os][:release][:major]} - #{facts[:os][:windows][:system32]}" do
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
        end

        context 'with default params' do
          let(:title) { 'Audit Logon' }
          let(:params) { {} }

          it { is_expected.to contain_file('C:/Windows/System32/GroupPolicy').with('ensure' => 'directory') }
          it { is_expected.to contain_file('C:/Windows/System32/GroupPolicy/Machine').with('ensure' => 'directory') }
          it { is_expected.to contain_file('C:/Windows/System32/GroupPolicy/Machine/Microsoft').with('ensure' => 'directory') }
          it { is_expected.to contain_file('C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT').with('ensure' => 'directory') }
          it { is_expected.to contain_file('C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit').with('ensure' => 'directory') }
          it { is_expected.to contain_file('C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv').with('ensure' => 'file') }
          it {
            is_expected.to contain_file_line('audit_csv_file_header')
              .with(
                'ensure' => 'present',
                'path' => 'C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv',
                'line' => 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value',
              )
          }
          it { is_expected.to contain_audit_policy('Logon').with('success' => 'disable', 'failure' => 'disable') }
          it {
            is_expected.to contain_file_line('audit_csv_line_{0cce9215-69ae-11d9-bed3-505054503030}')
              .with(
                'ensure' => 'present',
                'path'   => 'C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv',
                'line'   => ',System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},No Auditing,,0',
                'match'  => '^,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},',
              )
          }
        end

        context 'when configuring auditing policy, with naming exception' do
          let(:title) { 'auditing_policy' }
          let(:params) do
            {
              'policy'      => 'Audit Central Access Policy Staging',
              'success'     => 'enable',
              'failure'     => 'disable',
            }
          end

          it {
            is_expected.to contain_audit_policy('Central Policy Staging')
              .with(
                'success' => 'enable',
                'failure' => 'disable',
              )
          }

          it {
            is_expected.to contain_file_line('audit_csv_line_{0cce9246-69ae-11d9-bed3-505054503030}')
              .with(
                'ensure' => 'present',
                'path'   => 'C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv',
                'line'   => ',System,Audit Central Access Policy Staging,{0cce9246-69ae-11d9-bed3-505054503030},Success,,1',
                'match'  => '^,System,Audit Central Access Policy Staging,{0cce9246-69ae-11d9-bed3-505054503030},',
              )
          }
        end

        context 'when ensuring an auditing policy is absent' do
          let(:title) { 'Audit Kerberos Authentication Service' }
          let(:params) { { 'ensure' => 'absent' } }

          it { is_expected.not_to contain_audit_policy('Kerberos Authentication Service') }

          it {
            is_expected.to contain_file_line('audit_csv_line_{0cce9242-69ae-11d9-bed3-505054503030}')
              .with(
                'ensure' => 'absent',
                'path'   => 'C:/Windows/System32/GroupPolicy/Machine/Microsoft/Windows NT/Audit/audit.csv',
                'match'  => '^,System,Audit Kerberos Authentication Service,{0cce9242-69ae-11d9-bed3-505054503030},',
              )
          }
        end
      end
    end
  end
end
