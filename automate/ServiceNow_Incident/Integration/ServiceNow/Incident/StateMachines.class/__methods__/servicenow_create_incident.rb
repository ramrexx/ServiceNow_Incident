=begin
 servicenow_create_incident.rb

 Author: Kevin Morey <kevin@redhat.com>

 Description: This method creates a ServiceNow Incident Record via REST API
-------------------------------------------------------------------------------
   Copyright 2016 Kevin Morey <kevin@redhat.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-------------------------------------------------------------------------------
=end
def log(level, msg, update_message = false)
  $evm.log(level, "#{msg}")
  @task.message = msg if @task && (update_message || level == 'error')
end

def call_servicenow(action, tablename='incident', body=nil)
  require 'rest_client'
  require 'json'
  require 'base64'

  servername = nil || $evm.object['servername']
  username   = nil   || $evm.object['username']
  password   = nil   || $evm.object.decrypt('password')
  url = "https://#{servername}/api/now/table/#{tablename}"

  params = {
    :method=>action, :url=>url,
    :headers=>{ :content_type=>:json, :accept=>:json, :authorization => "Basic #{Base64.strict_encode64("#{username}:#{password}")}" }
  }
  params[:payload] = body.to_json
  log(:info, "Calling url: #{url} action: #{action} payload: #{params}")

  snow_response = RestClient::Request.new(params).execute
  log(:info, "response headers: #{snow_response.headers}")
  log(:info, "response code: #{snow_response.code}")
  log(:info, "response: #{snow_response}")
  snow_response_hash = JSON.parse(snow_response)
  return snow_response_hash['result']
end

def get_hostname
  hostname = @object.hostnames.first rescue nil
  hostname.blank? ? (return @object.name) : (return hostname)
end

def get_ipaddress
  ip = @object.ipaddresses
  ip.blank? ? (return @object.hardware.ipaddresses || nil) : (return ip)
end

def get_operatingsystem
  @object.try(:operating_system).try(:product_name) ||
    @object.try(:hardware).try(:guest_os_full_name) ||
    @object.try(:hardware).try(:guest_os) || 'unknown'
end

def get_diskspace
  diskspace = @object.allocated_disk_storage
  return nil if diskspace.nil?
  return diskspace / 1024**3
end

def build_payload
  comments  = "VM: #{@object.name}\n"
  comments += "Hostname: #{get_hostname}\n"
  comments += "Guest OS Description: #{get_operatingsystem}\n"
  comments += "IP Address: #{get_ipaddress}\n"
  comments += "Provider: #{@object.ext_management_system.name}\n" unless @object.ext_management_system.nil?
  comments += "Cluster: #{@object.try(:ems_cluster).try(:name)}\n" unless @object.ems_cluster.nil?
  comments += "Host: #{@object.try(:host).try(:name)}\n" unless @object.host.nil?
  comments += "CloudForms Server: #{$evm.root['miq_server'].hostname}\n"
  comments += "Region Number: #{@object.region_number}\n"
  comments += "vCPU: #{@object.num_cpu}\n"
  comments += "vRAM: #{@object.mem_cpu}\n"
  comments += "Disks: #{@object.num_disks}\n"
  comments += "Power State: #{@object.power_state}\n"
  comments += "Storage Name: #{@object.try(:storage_name)}\n" unless @object.storage_name.nil?
  comments += "Allocated Storage: #{get_diskspace}\n"
  comments += "GUID: #{@object.guid}\n"
  comments += "Tags: #{@object.tags.inspect}\n"
  (body_hash ||= {})['comments'] = comments
  return body_hash
end

begin
  $evm.root.attributes.sort.each { |k, v| log(:info, "Root:<$evm.root> Attribute - #{k}: #{v}")}

  case $evm.root['vmdb_object_type']
  when 'vm', 'miq_provision'
    @task   = $evm.root['miq_provision']
    @object = @task.try(:destination) || $evm.root['vm']
  when 'automation_task'
    @task   = $evm.root['automation_task']
    @object = $evm.vmdb(:vm).find_by_name($evm.root['vm_name']) ||
      $evm.vmdb(:vm).find_by_id($evm.root['vm_id'])
  end

  exit MIQ_STOP unless @object

  body_hash = build_payload

  # object_name = 'Event' means that we were triggered from an Alert
  if $evm.root['object_name'] == 'Event'
    log(:info, "Detected Alert driven event")
    body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['miq_alert_description']}"
  elsif $evm.root['ems_event']
    # ems_event means that were triggered via Control Policy
    log(:info, "Detected Policy driven event")
    log(:info, "Inspecting $evm.root['ems_event']:<#{$evm.root['ems_event'].inspect}>")
    body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['ems_event'].event_type}"
  else
    unless $evm.root['dialog_miq_alert_description'].nil?
      log(:info, "Detected service dialog driven event")
      # If manual creation add dialog input notes to body_hash
      body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['dialog_miq_alert_description']}"
    else
      log(:info, "Detected manual driven event")
      # If manual creation add default notes to body_hash
      body_hash['short_description'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - Incident manually created"
    end

    # call servicenow
    log(:info, "Calling ServiceNow: incident information: #{body_hash.inspect}")
    servicenow_result = call_servicenow(:post, 'incident', body_hash)

    log(:info, "servicenow_result: #{servicenow_result.inspect}")
    log(:info, "number: #{servicenow_result['number']}")
    log(:info, "sys_id: #{servicenow_result['sys_id']}")
    log(:info, "state: #{servicenow_result['state']}")

    log(:info, "Adding custom attribute {:servicenow_incident_number => #{servicenow_result['number']}}")
    @object.custom_set(:servicenow_incident_number, servicenow_result['number'].to_s)
    log(:info, "Adding custom attribute {:servicenow_incident_sysid => #{servicenow_result['sys_id']}}")
    @object.custom_set(:servicenow_incident_sysid, servicenow_result['sys_id'].to_s)
    log(:info, "Resetting custom attribute {:servicenow_incident_state => #{servicenow_result['state']}}")
    @object.custom_set(:servicenow_incident_state, servicenow_result['state'].to_s)
  end

rescue => err
  log(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_STOP
end
