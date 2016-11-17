=begin
 servicenow_close_incident.rb

 Author: Kevin Morey <kevin@redhat.com>

 Description: This method closes a ServiceNow Incident Record via REST API
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

def call_servicenow(action, tablename='incident', sysid=nil, body=nil)
  require 'rest_client'
  require 'json'
  require 'base64'

  servername = nil || $evm.object['servername']
  username = nil   || $evm.object['username']
  password = nil   || $evm.object.decrypt('password')
  url = "https://#{servername}/api/now/table/#{tablename}/#{sysid}"

  params = {
    :method=>action, :url=>url,
    :headers=>{ :content_type=>:json, :accept=>:json, :authorization => "Basic #{Base64.strict_encode64("#{username}:#{password}")}" }
  }
  params[:payload] = body.to_json
  log(:info, "Calling url: #{url} action: #{action} payload: #{params}")

  RestClient.proxy = $evm.object['proxy_url'] unless $evm.object['proxy_url'].nil?

  snow_response = RestClient::Request.new(params).execute
  log(:info, "response headers: #{snow_response.headers}")
  log(:info, "response code: #{snow_response.code}")
  log(:info, "response: #{snow_response}")
  snow_response_hash = JSON.parse(snow_response)
  return snow_response_hash['result']
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

  servicenow_incident_number = @object.custom_get(:servicenow_incident_number)
  log(:info, "Found custom attribute {:servicenow_incident_number=>#{servicenow_incident_number}} from #{@object.name}") if servicenow_incident_number
  servicenow_incident_sysid = @object.custom_get(:servicenow_incident_sysid)
  log(:info, "Found custom attribute {:servicenow_incident_sysid=>#{servicenow_incident_sysid}} from #{@object.name}") if servicenow_incident_sysid

  raise "missing servicenow_incident_sysid" if servicenow_incident_sysid.nil?

  body_hash = {}

  # as per snow documentation state '7' = 'closed'
  body_hash['state'] = '7'

  # object_name = 'Event' means that we were triggered from an Alert
  if $evm.root['object_name'] == 'Event'
    log(:info, "Detected Alert driven event")
    body_hash['comments'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['miq_alert_description']}"
  elsif $evm.root['ems_event']
    # ems_event means that were triggered via Control Policy
    log(:info, "Detected Policy driven event")
    log(:info, "Inspecting $evm.root['ems_event']:<#{$evm.root['ems_event'].inspect}>")
    body_hash['comments'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['ems_event'].event_type}"
  else
    unless $evm.root['dialog_miq_alert_description'].nil?
      log(:info, "Detected service dialog driven event")
      # If manual creation add dialog input notes to body_hash
      body_hash['comments'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - #{$evm.root['dialog_miq_alert_description']}"
    else
      log(:info, "Detected manual driven event")
      # If manual creation add default notes to body_hash
      body_hash['comments'] = "#{$evm.root['vmdb_object_type']}: #{@object.name} - Incident manually closed"
    end
  end

  # call servicenow
  log(:info, "Calling ServiceNow: incident information: #{body_hash.inspect}")
  servicenow_result = call_servicenow(:put, 'incident', servicenow_incident_sysid, body_hash)

  log(:info, "servicenow_result: #{servicenow_result.inspect}")
  log(:info, "number: #{servicenow_result['number']}")
  log(:info, "sys_id: #{servicenow_result['sys_id']}")
  log(:info, "state: #{servicenow_result['state']}")

  log(:info, "Setting custom attribute {:servicenow_incident_number => nil}")
  @object.custom_set(:servicenow_incident_number, nil)
  log(:info, "Setting custom attribute {:servicenow_incident_sysid => nil}")
  @object.custom_set(:servicenow_incident_sysid, nil)
  log(:info, "Setting custom attribute {:servicenow_incident_state => nil}")
  @object.custom_set(:servicenow_incident_state, nil)

rescue => err
  log(:error, "[#{err}]\n#{err.backtrace.join("\n")}")
  exit MIQ_STOP
end
