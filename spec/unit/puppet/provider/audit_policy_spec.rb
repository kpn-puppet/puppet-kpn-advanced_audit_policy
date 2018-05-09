# frozen_string_literal: true

require 'spec_helper'

provider_resource = Puppet::Type.type(:audit_policy)
provider_class    = provider_resource.provider(:auditpol)

describe provider_class do
  subject { provider_class }

  let(:resource) do
    provider_resource.new(
      subcategory: 'Logon',
      success:     :enable,
      failure:     :disable,
    )
  end

  let(:provider) { described_class.new(resource) }

  describe 'provider' do
    it 'will be an instance of Puppet::Type::audit_policy::auditpol' do
      expect(provider).to be_an_instance_of Puppet::Type::Audit_policy::ProviderAuditpol
    end

    it 'will respond to function calls' do
      expect(provider).to respond_to(:success)
      expect(provider).to respond_to(:failure)
      expect(provider).to respond_to(:flush)
      expect(provider.class).to respond_to(:instances)
      expect(provider.class).to respond_to(:prefetch)
    end

    describe 'instances' do
      it 'will return policy properties' do
        policies = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
          TLT0117,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Failure,'
        provider.class.stubs(auditpol: policies)
        provider.class.expects(:new).with(name: 'Logon', success: 'disable', failure: 'enable')
        provider.class.instances
      end
    end

    describe 'flush' do
      it 'will try and call auditpol in order to set auditing policies' do
        provider.class.stubs(:audit_policy)
        provider.instance_variable_set(:@property_flush, subcategory: 'Logon', success: :enable, failure: :disable)
        provider.expects(:auditpol).with(['/set', '/subcategory:Logon', '/success:enable', '/failure:disable'])
        provider.flush
      end
    end

    describe 'self.' do
      describe 'prefetch' do
        context 'with valid resource' do
          it 'will store prov into resource.provider' do
            prov_mock = mock
            prov_mock.expects(:name).returns('foo')
            resource_mock = mock
            resource_mock.expects(:provider=)
            resources = {}
            resources['foo'] = resource_mock
            provider.class.stubs(instances: [prov_mock])
            provider.class.prefetch(resources)
          end
        end
      end
    end
  end
end
