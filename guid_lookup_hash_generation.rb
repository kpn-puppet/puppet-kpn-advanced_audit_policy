#!/usr/bin/env ruby
# This script is to create an auditpol hash based on the current advanced auditpol of the local Windows system.
# This code can be used to perodicially update the auditpol manifest hash as seen within the advanced_audit_policy automatically.
# Run this script on a Windows system and execute this file within manifests folder containing the config.pp file and it will automatically update the $guid_lookup_hash table with the correct values.
# This script should be run with every revision and update of Windows operating system to account for new differences added within the auditpol - Example: 1903 --> 1909 or Windows 8.1 to 10
# Run this script from the main puppet module resource folder on a Windows system to update the manifest file or specify a manifest file

    require 'open3'
    require 'csv'
    require 'pp'
    require 'optparse'
    require 'optparse/time'
    require 'optparse'
    # options = {}
    # OptionParser.new do |opts|
    # opts.banner = "Usage: guid_lookup_generation.rb [options]"

    # opts.on("-f", "--file-path FILE") do |file|
    #     options[:file_path] = file || ".\\manifests\\config.pp"
    # end
    # end.parse!
    # p options[:file_path].to_s

    #Create AuditPolicy class to define values required
    class AuditPolicy <
        Struct.new(:Machine_Name,:Policy_Target,:Subcategory,:Subcategory_GUID,:Inclusion_Setting,:Exclusion_Setting)
    end

    # Create a temp file to store the auditpolicy csv file into
    auditpol_tmp_file = String.new()
    auditpol_tmp_file = Time.now.strftime('%Y-%m-%d_%H-%M-%S')
    auditpol_tmp_file.concat("-tmp-auditpol.csv")

    # Define auditpol exe parameters and start conditions - Assumes auditpol.exe is located in default Windows location
    auditpol = "auditpol.exe "
    auditpol << "/get "
    auditpol << "/category:* "
    auditpol << "/r"

    # Create stdout and stderr variables to store outputs
    stdout_str = ""
    stderr_str = ""

    # Open the file and parse with Open3 - native Ruby module
    # Parse stdout and remove the double extra newline if found within the file
    Open3.popen3(auditpol) do |stdin, stdout, stdeer, wait_thr|
        stdin.close
        stdout_str = stdout.read
        stdout_str = stdout_str.gsub("\n\n", "\n")
        stderr_str = stdeer.read
        status = wait_thr.value
    end

    # Write auditpol /get policy results to the temp file defined above - will save to executing folder location
    File.open(auditpol_tmp_file, "w") do |file|
        file.puts [stdout_str]
    end

    # Read in auditpol csv from system
    auditpol_csv = CSV.read(auditpol_tmp_file)
    # Retrieve header from the top row
    headers = auditpol_csv.shift.map {|i| i.to_s}
    # Convert each row from each cell and store as a string variable
    auditpol_csv_str = auditpol_csv.map { |row| row.map { |cell| cell.to_s } }
    # Map each row with each cell as defined by the header map as defined from the string variable
    auditpol_hash = Hash.new()
    auditpol_hash = auditpol_csv_str.map {|row| Hash[*headers.zip(row).flatten]}
    # Clean up auditpol array - Remove any nil, empty, or double next lines
    auditpol_hash = auditpol_hash.compact.reject(&''.method(:==))
    auditpol_hash = auditpol_hash.compact
    auditpol_hash = auditpol_hash.compact.select{|i| !i.to_s.empty?}

    # Remove each of the non-needed values from the array
    auditpol_hash_values_to_delete = ["Machine Name","Policy Target","Inclusion Setting","Exclusion Setting"]
    auditpol_hash_values_to_delete.each { |v| auditpol_hash = auditpol_hash.each { |k| k.delete(v) } }

    # Map each of the remaining values and flatten to one array struct
    auditpol_hash.map{|h| h.map{|i,j| j} }.flatten

    #auditpol_hash.map{ |s| s.map{ |i,j| j } }.flatten.uniq

    # Extract each key which contains two values - "Subcategory" and "Subcategory GUID"
    auditpol_hash.map{|k| k.map}.flatten

    # Create new hash to store final results into
    auditpol_hash_final = Hash.new()

    # For each key value from auditpol_hash --> store the values of "Subcategory" and "Subcategory GUID" into a new key:value formed off of the values of each element "Subcategory" and "Subcategory GUID" defined
    # Example:
    # Input:
    # {"Subcategory"=>"Plug and Play Events", "Subcategory GUID"=>"{0CCE9248-69AE-11D9-BED3-505054503030}"}
    # Transformation #
    # Output:
    # "Plug and Play Events"=>"{0CCE9248-69AE-11D9-BED3-505054503030}"
    auditpol_hash_final = auditpol_hash.map { |k| k.values}.uniq
    auditpol_hash_final = auditpol_hash_final.to_h
    auditpol_hash_final = auditpol_hash_final.sort.to_h
    # Return auditpol_hash_final hash
    # Print auditpol_hash_final has to screen
    #p auditpol_hash_final.to_h

    # Create new output string to convert the hash to the config.pp file --> must be in a string format for file purposes and formatting
    output_str = String.new()
    output_str = auditpol_hash_final.to_s
    output_str = output_str.gsub("}\"}", "}\",}")

    output_final_start_str = "\$guid_lookup_hash = \n"

    output_final_str = String.new()
    output_final_str.concat(output_final_start_str, output_str)
    output_final_str = output_final_str.gsub("\",", "\",\n")

    # Open the manifest file has configured - default is config.pp
    # Replace the file contents of anything within the $guid_lookup_hash variable with the contents of hash table created within the script here
    # It will always update the file if to match
    #manifest_files = options[:file_path]

    file_path = ".\\manifests\\config.pp"
    file = File.read(file_path)
    file_contents = file.gsub(/\$guid_lookup_hash\s=\s*{.*["|'],[\n|\r]\s*}/m, %{#{output_final_str}})
    puts file_contents
    File.open(file_path,"w") {|f| f.puts file_contents}
    #end


    # manifest_files.each do |manifest_file|
    #     file = File.read(manifest_file)
    #     file_contents = file.gsub(/\$guid_lookup_hash\s=\s*{.*["|'],[\n|\r]\s*}/m, %{#{output_final_str}})
    #     puts file_contents
    #     File.open(manifest_file, "w") {|f| f.puts file_contents}
    # end

    # Remove the tmp file once complete
    File.delete(auditpol_tmp_file)

#Guid_Lookup_Hash_Generation.guid_lookup_hash(ARGV[0])
#Guid_Lookup_Hash_Generation.guid_lookup_hash(ARGV[0])
