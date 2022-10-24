import base64
import bjoern
import boto3
import logging
import os
import re
import requests
import time

from flask import Flask, json, request
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

elastic_url = "https://localhost:9200"
api = Flask(__name__)

# Get IMDSv2 Metadata
# equivalent commands
# : curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# : curl -s http://169.254.169.254/latest/meta-data/placement/region -H "X-aws-ec2-metadata-token: <token>"
imdsv2_auth_token = (requests.put('http://169.254.169.254/latest/api/token', headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'})).text
imdsv2_region = (requests.get('http://169.254.169.254/latest/meta-data/placement/region', headers={'X-aws-ec2-metadata-token': imdsv2_auth_token})).text
imdsv2_instance_id = (requests.get('http://169.254.169.254/latest/meta-data/instance-id', headers={'X-aws-ec2-metadata-token': imdsv2_auth_token})).text

os.environ["AWS_DEFAULT_REGION"] = imdsv2_region

# API's 
####################################################

# Checks that the API is up without risk of sending bad requests
@api.route('/ping', methods=['GET'])
def ping():
    return "pong"

# Creates/serves the enrollment token
@api.route("/create_enrollment_token", methods=['POST'])
def enrollement_token():
    scope = None
    task_id = None
    response_message = { 'status' : 500 }
    
    json_body = request.json()
    
    if auth_check(json_body['apiKey']):
        
        if json_body['scope'] and json_body['scope'] == 'kibana':
            # Quickly search the scope if the task_id is passed in or search all logs manually
            if json_body['task_id']:
                results = kibana_cloudwatch_logs_searcher(task_id=json_body['task_id'])
            else:
                results = kibana_cloudwatch_logs_searcher()
                
            for item in results:
                if request.remote_addr == item['ip']:
                    enroll_token = create_enrollment_token(item['task_id'], json_body['scope'])
                    resp = requests.post(
                        url=f"http://{item['ip']}:5601/internal/interactive_setup/enroll",
                        data={
                            'hosts': enroll_token['hosts'],
                            'apiKey': enroll_token['apiKey'],
                            'caFingerprint': enroll_token['caFingerprint'],
                            'code': item['code']
                        },
                        headers={
                            "Content-Type": "application/json",
                            "Accept": "*/*"
                        }
                    )
                    
            if resp.status_code == 204:
                response_message['status'] = 200
            else:
                response_message['status'] = resp.status_code
                
            
        elif json_body['scope'] == 'elasticsearch':
            if 'task_id' not in json_body:
                response_message['status'] = 400
            else: 
                enroll_token = create_enrollment_token(task_id, 'scope')
                response_message['enrollment_token'] = enroll_token
                
                
        return json.dumps(response_message)
    
    return "Unauthorized", 401        
    
####################################################


# Code/Logic

def auth_check(valueToValidate):
    sm_client = boto3.client('secretsmanager')
    sm_resp = sm_client.get_secret_value(SecretId=os.getenv('ENROLLMENT_HELPER_SECRET_ARN')) 
    auth_key = sm_resp['authorizationKey']
    
    if auth_key == valueToValidate:
        return True

    return False

# Create the enrollment token -- service agnostic
def create_enrollment_token(task_id, scope):
    asg_cluster_name = os.getenv("EC2_ASG_CLUSTER_NAME")
    asg_client = boto3.client('autoscaling')
    asg_instances = asg_client.describe_auto_scaling_instances()
    
    stable_instance_ids = []
    for i in asg_instances['AutoScalingInstances']:
        if asg_cluster_name in i['AutoScalingGroupName']:
            if i['LifecycleState'] == 'InService':
                stable_instance_ids.append(i['InstanceId'])
    
    
    ec2_client = boto3.client('ec2')
    ec2_results = ec2_client.describe_instances(InstanceIds=stable_instance_ids)
    
    ec2_instance_ips = [i['NetworkInterfaces']['PrivateIpAddresses'][0]['PrivateIpAddress'] for i in ec2_results['Reservations']['Instances']]
    ec2_hosts = [f"https://{ip}:9200" for ip in ec2_instance_ips]
    
    
    sm_client = boto3.client('secretsmanager')
    sm_resp = sm_client.get_secret_value(SecretId=os.getenv('USER_SECRET_ARN'))         
    
    info_dict =  {
        'username': sm_resp['elastic_username'],
        'password': sm_resp['elastic_password'],
        'caFingerprint': sm_resp['ca_fingerprint']
    }
    
    # Generate the API Key for the Elastic User
    req = requests.post(
            f"{elastic_url}/_security/api_key",
            headers={'Content-Type': 'application/json'},
            auth=HTTPBasicAuth(info_dict['username'], info_dict['password']),
            data={
                'name': 'AutoGeneratedAPIKeyForEnrollment',
                'expiration': '1m',
                'metadata': {
                    'task_id': task_id,
                    'application_type': scope
                }
            },
            verify=False
        )
    
    node_resp = requests.get(elastic_url, auth=HTTPBasicAuth(info_dict['username'], info_dict['password']), verify=False)
    
    return {
        { 
        "version": node_resp.json()['version']['number'],
        "hosts": ec2_hosts,
        "apiKey": req.json()['encoded'],
        "caFingerprint": info_dict['caFingerprint'],
        }
    }
    
        
# Search cloudwatch logs for the kibana code
def kibana_cloudwatch_logs_searcher(task_id=None):
    ecs_cluster_name = os.getenv("ECS_CLUSTER_NAME")
    ecs_family_name  = os.getenv("ECS_TASK_FAMILY_NAME")
    
    cw_logs_client = boto3.client('logs')
    ecs_client     = boto3.client('ecs')
    code_pattern   = re.compile("\d{6}")
    kibana_codes   = []
    task_ids       = []
    
    if task_id:
        task_ids = [task_id]
    else:
        list_task_resp = ecs_client.list_tasks(
            cluster='logging_cluster',
            family='logging-kibana',
            desiredStatus='RUNNING'
        )
        
        task_ids = [id.split('/')[-1] for id in list_task_resp['taskArns']]
        
        
    task_details = ecs_client.describe_tasks(cluster='logging_cluster', tasks=task_ids)['tasks']

    for id in task_ids: 
        kibana_codes.append({
            'task_id': id,
            'code': None,
            'ip': ([i['containers'][0]['networkInterfaces'][0]['privateIpv4Address'] for i in task_details if id in i['taskArn']])[0]
        })
    
    log_streams = cw_logs_client.describe_log_streams(logGroupName='logging-kibana-ecs')['logStreams']
    active_log_streams = [stream for stream in log_streams if stream['logStreamName'].split('/')[-1] in task_ids]

    

    for stream in active_log_streams:
        stream_events = cw_logs_client.get_log_events(
            logGroupName='logging-kibana-ecs',
            logStreamName=stream['logStreamName']
        )
        for entry in stream_events['events']:
            if 'Go to http://0.0.0.0:5601' in entry['message']:
                kibana_codes[(stream['logStreamName'].split('/')[-1])] = code_pattern.findall(entry['message'])[-1]
    
    return kibana_codes


def register_local_elasticsearch_instance():
    asg_cluster_name = os.getenv("EC2_ASG_CLUSTER_NAME")
    asg_client = boto3.client('autoscaling')
    asg_instances = asg_client.describe_auto_scaling_instances()

    stable_instance_ids = []
    for i in asg_instances['AutoScalingInstances']:
        if asg_cluster_name in i['AutoScalingGroupName']:
            if i['LifecycleState'] == 'InService':
                stable_instance_ids.append(i['InstanceId'])
    
    
    ec2_client = boto3.client('ec2')
    ec2_results = ec2_client.describe_instances(InstanceIds=stable_instance_ids)
    
    ec2_instance_ips = [i['Instances'][0]['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['PrivateIpAddress'] for i in ec2_results['Reservations']]
    ec2_hosts = [f"https://{ip}:7001" for ip in ec2_instance_ips]
    
    for ec2_instance in ec2_hosts:
        try:
            logging.info(f"Trying instance {ec2_instance}")
            helper_response = requests.get(f"{ec2_instance}/ping")
            if "pong" in helper_response.text:
                enroll_token = create_enrollment_token(imdsv2_instance_id, 'elasticsearch')
                logging.info("Elasticsearch was successfully enrolled.")
                break
            
        except requests.RequestException as e:
            logging.error(f"Error encountered in connection to {ec2_instance}: {e}")
    
    os.system(f"/usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token { base64.b64encode(enroll_token) }")



def check_cluster_health():
    sm_client = boto3.client('secretsmanager')
    sm_resp = sm_client.get_secret_value(SecretId=os.getenv('USER_SECRET_ARN'))         
    
    info_dict =  {
        'username': sm_resp['elastic_username'],
        'password': sm_resp['elastic_password'],
        'caFingerprint': sm_resp['ca_fingerprint']
    }
    
    def check_health():
        health_status_response = requests.get(
            f"{elastic_url}/_cluster/health",
            auth=HTTPBasicAuth(info_dict['username'], info_dict['password']),
            verify=False
        )
        return health_status_response.json()['status']
    
    
    status = check_health()
    while status != 'green':
        logging.info("Status is not Green, waiting for thirty seconds and trying again")
        time.sleep(30)
        status = check_health()
        
    lifecycle_client = boto3.client('autoscaling')
    resp = lifecycle_client.complete_lifecycle_action(
        LifecycleHookName='sync_elasticsearch',
        AutoScalingGroupName=os.getenv("EC2_ASG_CLUSTER_NAME"),
        InstanceId=imdsv2_instance_id
    )


if __name__ == '__main__':
    register_local_elasticsearch_instance()
    check_cluster_health()
    bjoern.run(api, "0.0.0.0", 7001)