# frozen_string_literal: true

require 'spec_helper'

provider_resource = Puppet::Type.type(:audit_policy)
provider_class    = provider_resource.provider(:auditpol)

describe provider_class, if: RUBY_PLATFORM =~ %r{cygwin|mswin|mingw|bccwin|wince|emx} do
  subject { provider_class }

  let(:resource) do
    provider_resource.new(
      subcategory: 'Logon',
      success: :enable,
      failure: :disable,
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
        allow(provider.class).to receive(:auditpol).and_return(policies)
        expect(provider.class).to respond_to(:instances)
      end
    end

    describe 'flush' do
      it 'will try and call auditpol in order to set auditing policies' do
        allow(provider.class).to receive(:audit_policy)
        expect(provider).to receive(:auditpol).with(['/set', '/subcategory:Logon'])
        provider.flush
      end
    end

    describe 'self.' do
      let(:provider) do
        described_class.new
      end

      describe 'prefetch' do
        context 'with valid resource' do
          it 'will store prov into resource.provider' do
            prov_mock = instance_double('Provider', name: 'foo')
            resource_mock = instance_double('Resource')
            expect(resource_mock).to receive(:provider=)
            resources = {}
            resources['foo'] = resource_mock
            allow(provider.class).to receive(:instances).and_return([prov_mock])
            provider.class.prefetch(resources)
          end
        end
      end
    end
  end
end
