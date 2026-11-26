# frozen_string_literal: true

require 'spec_helper'

provider_resource = Puppet::Type.type(:audit_policy)
provider_class    = provider_resource.provider(:auditpol)

describe provider_class do
  let(:backup_header) { "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n" }

  # Output of `auditpol /backup` on a zh-TW host: subcategory names and inclusion
  # settings are localized, GUIDs and setting values are not.
  let(:localized_backup) do
    "#{backup_header}TLT0117,系統,登入,{0CCE9215-69AE-11D9-BED3-505054503030},失敗,,2\r\n" \
      "TLT0117,系統,認證驗證,{0CCE923F-69AE-11D9-BED3-505054503030},成功與失敗,,3\r\n" \
      "TLT0117,系統,登出,{0CCE9216-69AE-11D9-BED3-505054503030},成功,,1\r\n" \
      "TLT0117,系統,帳戶鎖定,{0CCE9217-69AE-11D9-BED3-505054503030},沒有稽核,,0\r\n" \
      "TLT0117,S-1-5-21-1-2-3-1001,登入,{0CCE9215-69AE-11D9-BED3-505054503030},成功與失敗,,3\r\n" \
      "TLT0117,,Option:CrashOnAuditFail,,Disabled,,0\r\n" \
      "TLT0117,,RegistryGlobalSacl,,,,\r\n"
  end

  let(:english_backup) do
    "#{backup_header}TLT0117,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Failure,,2\r\n" \
      "TLT0117,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1\r\n"
  end

  let(:resource) do
    provider_resource.new(
      subcategory: 'Logon',
      success: :enable,
      failure: :disable,
    )
  end

  let(:guid_resource) do
    provider_resource.new(
      subcategory: 'Logon',
      guid: '{0CCE9215-69AE-11D9-BED3-505054503030}',
      success: :enable,
      failure: :disable,
    )
  end

  def utf16le_with_bom(str)
    "\xFF\xFE".b + str.encode(Encoding::UTF_16LE).b
  end

  describe 'provider' do
    it 'is an instance of Puppet::Type::Audit_policy::ProviderAuditpol' do
      expect(described_class.new(resource)).to be_an_instance_of Puppet::Type::Audit_policy::ProviderAuditpol
    end

    it 'responds to function calls' do
      provider = described_class.new(resource)
      expect(provider).to respond_to(:success)
      expect(provider).to respond_to(:failure)
      expect(provider).to respond_to(:guid)
      expect(provider).to respond_to(:flush)
      expect(described_class).to respond_to(:instances)
      expect(described_class).to respond_to(:prefetch)
    end
  end

  describe 'parse_backup' do
    it 'parses UTF-16LE output with a byte order mark' do
      policies = described_class.parse_backup(utf16le_with_bom(localized_backup))
      expect(policies).to eq(
        [
          { name: '登入', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable' },
          { name: '認證驗證', guid: '{0cce923f-69ae-11d9-bed3-505054503030}', success: 'enable', failure: 'enable' },
          { name: '登出', guid: '{0cce9216-69ae-11d9-bed3-505054503030}', success: 'enable', failure: 'disable' },
          { name: '帳戶鎖定', guid: '{0cce9217-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'disable' },
        ],
      )
    end

    it 'parses UTF-8 output with a byte order mark' do
      policies = described_class.parse_backup("\xEF\xBB\xBF".b + localized_backup.b)
      expect(policies.map { |p| p[:guid] }).to eq(
        [
          '{0cce9215-69ae-11d9-bed3-505054503030}',
          '{0cce923f-69ae-11d9-bed3-505054503030}',
          '{0cce9216-69ae-11d9-bed3-505054503030}',
          '{0cce9217-69ae-11d9-bed3-505054503030}',
        ],
      )
    end

    it 'parses output in a legacy code page' do
      legacy = "#{backup_header}TLT0117,系統,登入,{0CCE9215-69AE-11D9-BED3-505054503030},失敗,,2\r\n".encode('CP950')
      policies = described_class.parse_backup(legacy.b)
      expect(policies.length).to eq(1)
      expect(policies[0]).to include(guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable')
    end

    it 'keeps the system policy when a per-user policy has the same GUID' do
      policies = described_class.parse_backup(localized_backup)
      logon = policies.select { |p| p[:guid] == '{0cce9215-69ae-11d9-bed3-505054503030}' }
      expect(logon).to eq([{ name: '登入', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable' }])
    end

    it 'ignores a per-user row that precedes the system row' do
      backup = "#{backup_header}PC,S-1-5-21-1-2-3-1001,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3\r\n" \
               "PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Failure,,2\r\n"
      expect(described_class.parse_backup(backup)).to eq([{ name: 'Logon', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'disable', failure: 'enable' }])
    end

    it 'keeps the full name when a localized subcategory name contains a comma' do
      backup = "#{backup_header}TLT0117,System,Logon, Logoff,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\r\n"
      expect(described_class.parse_backup(backup)).to eq([{ name: 'Logon, Logoff', guid: '{0cce9215-69ae-11d9-bed3-505054503030}', success: 'enable', failure: 'disable' }])
    end

    it 'skips rows with an unknown setting value' do
      allow(Puppet).to receive(:warning)
      backup = "#{backup_header}TLT0117,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,9\r\n"
      expect(described_class.parse_backup(backup)).to eq([])
    end

    it 'warns when data rows are present but none can be parsed' do
      expect(Puppet).to receive(:warning).with(%r{no subcategory rows could be parsed})
      bomless_utf16 = "#{backup_header}PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,,1\r\n".encode(Encoding::UTF_16LE).b
      expect(described_class.parse_backup(bomless_utf16)).to eq([])
    end

    it 'returns nothing for a header-only file without warning' do
      expect(Puppet).not_to receive(:warning)
      expect(described_class.parse_backup(backup_header)).to eq([])
    end
  end

  describe 'read_backup' do
    it 'calls auditpol /backup with a Windows path and returns the file contents' do
      allow(Dir).to receive(:mktmpdir).with('audit_policy').and_yield('C:/tmp/ap')
      expect(described_class).to receive(:auditpol).with('/backup', '/file:C:\\tmp\\ap\\auditpol_backup.csv')
      allow(File).to receive(:binread).with('C:/tmp/ap/auditpol_backup.csv').and_return('contents')
      expect(described_class.read_backup).to eq('contents')
    end
  end

  describe 'instances' do
    it 'returns one provider per system subcategory' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(localized_backup))
      instances = described_class.instances
      expect(instances.map(&:guid)).to eq(
        [
          '{0cce9215-69ae-11d9-bed3-505054503030}',
          '{0cce923f-69ae-11d9-bed3-505054503030}',
          '{0cce9216-69ae-11d9-bed3-505054503030}',
          '{0cce9217-69ae-11d9-bed3-505054503030}',
        ],
      )
      expect(instances.map(&:name)).to eq(%w[登入 認證驗證 登出 帳戶鎖定])
    end
  end

  describe 'flush' do
    it 'uses the name when no GUID is set' do
      provider = described_class.new(resource)
      provider.success = :enable
      provider.failure = :disable
      expect(provider).to receive(:auditpol).with(['/set', '/subcategory:Logon', '/success:enable', '/failure:disable'])
      provider.flush
    end

    it 'uses the GUID instead of the name when one is set' do
      provider = described_class.new(guid_resource)
      provider.success = :enable
      provider.failure = :disable
      expect(provider).to receive(:auditpol).with(['/set', '/subcategory:{0cce9215-69ae-11d9-bed3-505054503030}', '/success:enable', '/failure:disable'])
      provider.flush
    end

    it 'only passes the properties that changed' do
      provider = described_class.new(guid_resource)
      provider.failure = :disable
      expect(provider).to receive(:auditpol).with(['/set', '/subcategory:{0cce9215-69ae-11d9-bed3-505054503030}', '/failure:disable'])
      provider.flush
    end
  end

  describe 'prefetch' do
    it 'matches a localized policy by GUID' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(localized_backup))
      described_class.prefetch('Logon' => guid_resource)
      expect(guid_resource.provider.guid).to eq('{0cce9215-69ae-11d9-bed3-505054503030}')
      expect(guid_resource.provider.success).to eq('disable')
      expect(guid_resource.provider.failure).to eq('enable')
    end

    it 'matches by name when no GUID is set' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(english_backup))
      described_class.prefetch('Logon' => resource)
      expect(resource.provider.guid).to eq('{0cce9215-69ae-11d9-bed3-505054503030}')
      expect(resource.provider.success).to eq('disable')
      expect(resource.provider.failure).to eq('enable')
    end

    it 'does not match a localized policy by English name' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(localized_backup))
      original = resource.provider
      described_class.prefetch('Logon' => resource)
      expect(resource.provider).to equal(original)
    end

    it 'leaves the provider unchanged when the GUID is not in the backup' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(english_backup))
      missing = provider_resource.new(
        subcategory: 'Removable Storage',
        guid: '{0cce9245-69ae-11d9-bed3-505054503030}',
        success: :enable,
        failure: :enable,
      )
      original = missing.provider
      described_class.prefetch('Removable Storage' => missing)
      expect(missing.provider).to equal(original)
    end

    it 'accepts resources for different subcategories' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(english_backup))
      logoff = provider_resource.new(subcategory: 'Logoff', success: :enable, failure: :disable)
      expect { described_class.prefetch('Logon' => guid_resource, 'Logoff' => logoff) }.not_to raise_error
      expect(guid_resource.provider.guid).to eq('{0cce9215-69ae-11d9-bed3-505054503030}')
      expect(logoff.provider.guid).to eq('{0cce9216-69ae-11d9-bed3-505054503030}')
    end

    it 'rejects two resources that declare the same GUID' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(english_backup))
      first = provider_resource.new(
        subcategory: 'Removable Storage',
        guid: '{0cce9245-69ae-11d9-bed3-505054503030}',
        success: :enable,
        failure: :disable,
      )
      second = provider_resource.new(
        subcategory: 'Removable Storage 2',
        guid: '{0CCE9245-69AE-11D9-BED3-505054503030}',
        success: :disable,
        failure: :enable,
      )
      expect {
        described_class.prefetch('Removable Storage' => first, 'Removable Storage 2' => second)
      }.to raise_error(Puppet::Error, %r{Removable Storage and Removable Storage 2 both manage subcategory \{0cce9245-69ae-11d9-bed3-505054503030\}})
    end

    it 'rejects a name-only resource and a GUID resource for the same subcategory' do
      allow(described_class).to receive(:read_backup).and_return(utf16le_with_bom(english_backup))
      by_guid = provider_resource.new(
        subcategory: 'Logon by GUID',
        guid: '{0cce9215-69ae-11d9-bed3-505054503030}',
        success: :disable,
        failure: :enable,
      )
      expect {
        described_class.prefetch('Logon' => resource, 'Logon by GUID' => by_guid)
      }.to raise_error(Puppet::Error, %r{Logon and Logon by GUID both manage subcategory \{0cce9215-69ae-11d9-bed3-505054503030\}})
    end
  end
end
