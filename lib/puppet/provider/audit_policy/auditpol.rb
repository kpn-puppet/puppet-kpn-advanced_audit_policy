# frozen_string_literal: true

require 'tmpdir'

Puppet::Type.type(:audit_policy).provide(:auditpol) do
  confine    osfamily: :windows
  defaultfor osfamily: :windows

  commands auditpol: 'auditpol.exe'

  # This is a class method rather than a constant: constants defined inside a
  # `provide` block are scoped to the top level, not to the provider class.
  #
  # Maps the numeric "Setting Value" column of `auditpol /backup` output to
  # [success, failure]. Unlike the "Inclusion Setting" text, which auditpol.exe
  # localizes, this value is the same under every system locale.
  def self.setting_values
    {
      0 => %w[disable disable],
      1 => %w[enable disable],
      2 => %w[disable enable],
      3 => %w[enable enable],
    }
  end

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  def guid
    @property_hash[:guid]
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
      # Prefer the GUID: auditpol.exe does not resolve English subcategory names
      # on hosts with a non-English system locale, but accepts GUIDs everywhere.
      (options << '/set')
      (options << "/subcategory:#{resource[:guid] || resource[:subcategory]}")
      (options << "/success:#{resource[:success]}") if @property_flush[:success]
      (options << "/failure:#{resource[:failure]}") if @property_flush[:failure]
    end
    auditpol(options) unless options.empty?
    @property_hash = resource.to_hash
  end

  def self.instances
    parse_backup(read_backup).map do |policy|
      new(name: policy[:name],
          guid: policy[:guid],
          success: policy[:success],
          failure: policy[:failure])
    end
  end

  # Writes the current system audit policy to a temporary file with
  # `auditpol /backup` and returns the raw file contents.
  #
  # `auditpol /get /r` is not used because its subcategory names and inclusion
  # settings are localized; the backup file also carries a numeric setting value.
  def self.read_backup
    contents = nil
    Dir.mktmpdir('audit_policy') do |dir|
      # auditpol.exe has no overwrite option, so write to a new path inside a
      # fresh directory, which is removed afterwards.
      path = File.join(dir, 'auditpol_backup.csv')
      auditpol('/backup', "/file:#{path.tr('/', '\\')}")
      contents = File.binread(path)
    end
    contents
  end

  # Converts the raw `auditpol /backup` file contents to UTF-8.
  #
  # auditpol.exe writes UTF-16LE with a byte order mark on current Windows
  # releases. UTF-8 and BOM-less input are accepted as a fallback; only the
  # ASCII GUID and setting value columns are interpreted.
  def self.decode_backup(raw)
    raw = raw.b
    if raw.start_with?("\xFF\xFE".b)
      raw.byteslice(2..-1).force_encoding(Encoding::UTF_16LE)
         .encode(Encoding::UTF_8, invalid: :replace, undef: :replace)
    elsif raw.start_with?("\xEF\xBB\xBF".b)
      raw.byteslice(3..-1).force_encoding(Encoding::UTF_8).scrub
    else
      raw.force_encoding(Encoding::UTF_8).scrub
    end
  end

  # Parses `auditpol /backup` output into one hash per system subcategory.
  #
  # Columns: Machine Name, Policy Target, Subcategory, Subcategory GUID,
  # Inclusion Setting, Exclusion Setting, Setting Value. Rows without a
  # subcategory GUID (audit options, global resource SACLs) and per-user policy
  # rows (whose Policy Target is a SID) are skipped.
  def self.parse_backup(raw)
    policies = {}
    guid_column = %r{,(#{resource_type.guid_regex}),}
    lines = decode_backup(raw).each_line.drop(1)
    lines.each do |line|
      # Anchor on the GUID and the trailing setting value rather than on column
      # indexes, so a localized subcategory name containing a comma cannot shift
      # the columns. Everything before the GUID is machine, target, and name.
      guid_match = line.match(guid_column)
      value_match = line.match(%r{,(\d+)\s*\z})
      next unless guid_match && value_match

      _machine, target, name = line[0...guid_match.begin(0)].split(',', 3)
      next if name.nil?
      next if target.strip.start_with?('S-1-')

      # Skip unknown values so the resource is treated as out of sync and set.
      success, failure = setting_values[value_match[1].to_i]
      next unless success

      guid = guid_match[1].downcase
      policies[guid] ||= {
        name: name,
        guid: guid,
        success: success,
        failure: failure,
      }
    end
    if policies.empty? && lines.any? { |line| !line.strip.empty? }
      Puppet.warning('audit_policy: no subcategory rows could be parsed from auditpol /backup output; managed policies will be reapplied')
    end
    policies.values
  end

  def self.prefetch(resources)
    policies = instances
    # Puppet rejects duplicate titles and subcategory names, but not two
    # resources that resolve to the same subcategory GUID (a GUID and a name, or
    # two spellings). They would share one provider and overwrite each other's
    # settings, so fail instead.
    owners = {}
    resources.each do |name, resource|
      provider = if resource[:guid]
                   policies.find { |policy| policy.guid == resource[:guid] }
                 else
                   policies.find { |policy| policy.name == name }
                 end
      guid = resource[:guid] || provider&.guid
      if guid
        if (other = owners[guid])
          raise Puppet::Error, "audit_policy: #{[other.title, resource.title].sort.join(' and ')} both manage subcategory #{guid}"
        end

        owners[guid] = resource
      end
      resource.provider = provider if provider
    end
  end
end
