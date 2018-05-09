# frozen_string_literal: true

Puppet::Type.type(:audit_policy).provide(:auditpol) do
  confine    osfamily: :windows
  defaultfor osfamily: :windows

  commands auditpol: 'auditpol.exe'

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  def success
    @property_hash[:success]
  end

  def success=(value)
    @property_flush[:success] = value
  end

  def failure
    @property_hash[:failure]
  end

  def failure=(value)
    @property_flush[:failure] = value
  end

  def flush
    options = []
    if @property_flush
      (options << '/set')
      (options << "/subcategory:#{resource[:subcategory]}")
      (options << "/success:#{resource[:success]}") if @property_flush[:success]
      (options << "/failure:#{resource[:failure]}") if @property_flush[:failure]
    end
    auditpol(options) unless options.empty?
    @property_hash = resource.to_hash
  end

  def self.instances
    # generate a list of all categories and subcategories in csv
    categories = auditpol('/get', '/category:*', '/r')

    # the drop(1) drops the header line
    categories.split("\n").drop(1).map do |line|
      line_array = line.split(',')
      subcategory_name = line_array[2]
      subcategory_policy = line_array[4]

      case subcategory_policy
      when 'Success'
        success = 'enable'
        failure = 'disable'
      when 'Failure'
        success = 'disable'
        failure = 'enable'
      when 'Success and Failure'
        success = 'enable'
        failure = 'enable'
      when 'No Auditing'
        success = 'disable'
        failure = 'disable'
      else # disable all if something weird happened I guess
        success = 'disable'
        failure = 'disable'
      end

      new(name: subcategory_name,
          success: success,
          failure: failure)
    end
  end

  def self.prefetch(resources)
    policies = instances
    resources.keys.each do |name|
      if (provider = policies.find { |policy| policy.name == name })
        resources[name].provider = provider
      end
    end
  end
end
