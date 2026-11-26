# frozen_string_literal: true

require 'spec_helper'

type_class = Puppet::Type.type(:audit_policy)

describe type_class do
  let :params do
    [
      :subcategory,
    ]
  end

  let :properties do
    [
      :success,
      :failure,
    ]
  end

  it 'has expected properties' do
    properties.each do |property|
      expect(type_class.properties.map(&:name)).to be_include(property)
    end
  end

  it 'has expected parameters' do
    params.each do |param|
      expect(type_class.parameters).to be_include(param)
    end
  end

  it 'requires a subcategory' do
    expect {
      type_class.new({})
    }.to raise_error(Puppet::Error, 'Title or name must be provided')
  end

  it 'requires a success state' do
    expect {
      type_class.new(
        subcategory: 'Logon',
        Failure: :enable,
      )
    }.to raise_error(Puppet::Error, %r{Success parameter must be provided})
  end

  it 'requires a failure state' do
    expect {
      type_class.new(
        subcategory: 'Logon',
        Success: :enable,
      )
    }.to raise_error(Puppet::Error, %r{Failure parameter must be provided})
  end

  context 'with illegal subcategory value' do
    it 'will raise type error if subcategory is not a string' do
      params = { subcategory: 42, Failure: :enable, Success: :disable }
      expect { type_class.new(params) }.to raise_error(Puppet::Error, %r{Subcategory should be a String})
    end
  end

  context 'with illegal success/failure values' do
    it 'will raise illegal success value error ' do
      params = { subcategory: 'Logon', Failure: :enable, Success: 'illegal' }
      expect { type_class.new(params) }.to raise_error(Puppet::Error, %r{expected values :enable or :disable. got: illegal})
    end

    it 'raises illegal failure value error ' do
      params = { subcategory: 'Logon', Success: :enable, Failure: 'illegal' }
      expect { type_class.new(params) }.to raise_error(Puppet::Error, %r{expected values :enable or :disable. got: illegal})
    end
  end

  context 'with a guid' do
    it 'accepts and downcases a braced GUID' do
      resource = type_class.new(subcategory: 'Logon', guid: '{0CCE9215-69AE-11D9-BED3-505054503030}', success: :enable, failure: :disable)
      expect(resource[:guid]).to eq('{0cce9215-69ae-11d9-bed3-505054503030}')
    end

    it 'is optional' do
      resource = type_class.new(subcategory: 'Logon', success: :enable, failure: :disable)
      expect(resource[:guid]).to be_nil
    end

    it 'rejects a GUID without braces' do
      params = { subcategory: 'Logon', guid: '0cce9215-69ae-11d9-bed3-505054503030', success: :enable, failure: :disable }
      expect { type_class.new(params) }.to raise_error(Puppet::Error, %r{Guid should be of the form})
    end

    it 'rejects a non-string GUID' do
      params = { subcategory: 'Logon', guid: 42, success: :enable, failure: :disable }
      expect { type_class.new(params) }.to raise_error(Puppet::Error, %r{Guid should be a String})
    end
  end
end
