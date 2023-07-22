import json
import boto3
import os
import urllib.request

client = boto3.client('ec2')
STARTING_RULE_NUMBER = int(os.environ["STARTING_RULE_NUMBER"])
webhook_url = "https://slack_webhook_here"
def lambda_handler(event, context):
    message = event['Records'][0]['Sns']['Message'] #json.dumps(event, indent=2)
    config_data = json.loads(message)
    alert_type=config_data["detail"]["description"]

    if "unauthorized" in alert_type:
        ip_addresses = []
        for offending_ip in config_data["detail"]["service"]["action"]["networkConnectionAction"]:
            remote_ip_details = offending_ip["remoteIpDetails"]
            ip_addresses.append(remote_ip_details["ipAddressV4"])
        vpc_id = config_data["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["vpcId"]
        create_and_manage_rules(ip_addresses,STARTING_RULE_NUMBER,vpc_id,alert_type)
        
    elif "unprotected" in alert_type:
        ip_addresses = []
        for port_probe_details in config_data["detail"]["service"]["action"]["portProbeAction"]["portProbeDetails"]:
            remote_ip_details = port_probe_details["remoteIpDetails"]
            ip_addresses.append(remote_ip_details["ipAddressV4"])
        vpc_id = config_data["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["vpcId"]
        create_and_manage_rules(ip_addresses,STARTING_RULE_NUMBER,vpc_id,alert_type)
    else:
        print("no threat found in al")

def create_and_manage_rules(ip_list,STARTING_RULE_NUMBER,vpc_id,alert_type):
    for rule in ip_list:
        nacl_details = client.describe_network_acls(
                Filters=[{
                        'Name' : 'vpc-id',
                        'Values' : [vpc_id]
                    }],
                MaxResults=5)
        association = nacl_details['NetworkAcls'][0]
        network_acl = association['Associations'][0]['NetworkAclId']
        last_nacl_entry = nacl_details['NetworkAcls'][0]
        rule_numbers = []
        rule_cidr = []
        ips_created_rules = []
        ips_created_cidr = []
        for rules in last_nacl_entry['Entries']:
            rule_numbers.append(int(rules['RuleNumber']))
            rule_cidr.append(rules['CidrBlock'])
        for i in rule_numbers:
            if i >= 4000 and i < 5000:
                ips_created_rules.append(i)
                ips_created_cidr.append(rule_cidr[rule_numbers.index(i)])
        if len(ips_created_rules)>=10:
            oldest_rule = int(sorted(ips_created_rules)[0])
            newest_rule = int(sorted(ips_created_rules)[-1])
            oldest_cidr = ips_created_cidr[0]
            client.delete_network_acl_entry(
                NetworkAclId=network_acl,
                RuleNumber=oldest_rule,
                Egress=False )
            send_slack_message(webhook_url, f"{oldest_cidr} was removed from the blacklist because it reached the maximum limit.")
        elif len(ips_created_rules)==0:
            newest_rule=STARTING_RULE_NUMBER
        elif len(ips_created_rules)>0 and len(ips_created_rules)<10:
            newest_rule = int(sorted(ips_created_rules)[-1])
        newest_rule+=1

        response = client.create_network_acl_entry(
            CidrBlock=rule+"/24",
            Egress=False,
            NetworkAclId=network_acl,
            PortRange={
                'From': 1,
                'To': 65535,
            },
            Protocol = '-1',
            RuleAction = 'deny',
            RuleNumber=newest_rule,
            )
        send_slack_message(webhook_url, f"{rule} was blacklisted because {alert_type}")

def send_slack_message(webhook_url, message):
    payload = {
        'text': message
    }
    req = urllib.request.Request(webhook_url, method='POST')
    req.add_header('Content-Type', 'application/json')
    data = json.dumps(payload).encode('utf-8')
    req.data = data

    try:
        with urllib.request.urlopen(req) as response:
            pass
    except urllib.error.HTTPError as e:
        print(f"Failed to send Slack message. Error code: {e.code}")
    except urllib.error.URLError as e:
        print(f"Failed to send Slack message. Reason: {e.reason}")
