# frozen_string_literal: true

require 'beaker-rspec/spec_helper'
require 'beaker-rspec/helpers/serverspec'
require 'beaker/puppet_install_helper'

UNSUPPORTED_PLATFORMS = ['RedHat'].freeze

unless ENV['RS_PROVISION'] == 'no' || ENV['BEAKER_provision'] == 'no'
  # Install Puppet Enterprise Agent
  run_puppet_install_helper

  # Clone module dependencies
  system('git clone git@github.com:puppetlabs/puppetlabs-stdlib.git spec/fixtures/modules/stdlib')

  # Copy modules to SUT
  copy_module_to(hosts, source: 'spec/fixtures/modules/stdlib', module_name: 'stdlib')
end

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    puppet_module_install(source: proj_root, module_name: 'advanced_audit_policy')
  end
end
