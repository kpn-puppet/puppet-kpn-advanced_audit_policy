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
end
