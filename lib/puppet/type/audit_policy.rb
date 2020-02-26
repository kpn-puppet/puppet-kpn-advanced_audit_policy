# frozen_string_literal: true

Puppet::Type.newtype(:audit_policy) do
  desc 'audit_policy type for windows'

  newparam(:subcategory, namevar: true) do
    desc 'The subcategory of the policy.'
    validate do |value|
      raise 'Subcategory should be a String' unless value.is_a? String
    end
  end

  newproperty(:success) do
    desc 'Whether auditing is enabled on success or not'
    #defaultto :nil
    newvalues(:enable, :disable)
    #validate do |value|
    #  raise 'Success parameter must be provided' unless value != :nil
    #  raise "expected values :enable or :disable. got: #{value}" unless value.to_s =~ %r{^(enable|disable)$}
    #end
  end

  newproperty(:failure) do
    desc 'Whether auditing is enabled on failure or not'
    #defaultto :nil
    newvalues(:enable, :disable)
    #validate do |value|
    #  raise 'Failure parameter must be provided' unless value != :nil
    #  raise "expected values :enable or :disable. got: #{value}" unless value.to_s =~ %r{^(enable|disable)$}
    #end
  end
end
