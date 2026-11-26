# frozen_string_literal: true

Puppet::Type.newtype(:audit_policy) do
  desc 'audit_policy type for windows'

  # Matches a braced subcategory GUID such as
  # {0CCE9215-69AE-11D9-BED3-505054503030}. The provider uses it to find GUIDs
  # in `auditpol /backup` output.
  def self.guid_regex
    %r{\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}}i
  end

  newparam(:subcategory, namevar: true) do
    desc 'The subcategory of the policy.'
    validate do |value|
      raise 'Subcategory should be a String' unless value.is_a? String
    end
  end

  newparam(:guid) do
    desc <<-DESC
      The subcategory GUID, e.g. '{0cce9215-69ae-11d9-bed3-505054503030}'.
      When set, the provider identifies the subcategory by GUID instead of by
      name. auditpol.exe does not resolve English subcategory names on hosts
      with a non-English system locale; GUIDs work under every locale.
    DESC
    validate do |value|
      raise 'Guid should be a String' unless value.is_a? String
      unless value =~ %r{\A#{resource.class.guid_regex}\z}
        raise "Guid should be of the form {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}. got: #{value}"
      end
    end
    munge(&:downcase)
  end

  newproperty(:success) do
    desc 'Whether auditing is enabled on success or not'
    defaultto :nil
    newvalues(:enable, :disable)
    validate do |value|
      raise 'Success parameter must be provided' unless value != :nil
      raise "expected values :enable or :disable. got: #{value}" unless value.to_s =~ %r{^(enable|disable)$}
    end
  end

  newproperty(:failure) do
    desc 'Whether auditing is enabled on failure or not'
    defaultto :nil
    newvalues(:enable, :disable)
    validate do |value|
      raise 'Failure parameter must be provided' unless value != :nil
      raise "expected values :enable or :disable. got: #{value}" unless value.to_s =~ %r{^(enable|disable)$}
    end
  end
end
