# Security Groups

### How to find security group attachments
```python
import boto3
import argparse
import json
from pprint import pprint as pp
parser = argparse.ArgumentParser()
parser.add_argument("--sg", help="security group")
args = parser.parse_args()

def find_all_ec2():
    client = boto3.client('ec2')
    return client.describe_instances()['Reservations']


def find_all_elb():
    """
    'LoadBalancers': [{'LoadBalancerArn': 'arn:aws:elasticloadbalancing:eu-west-1:216393279172:loadbalancer/net/Splunk-syslog-LB/952a4c2f4d4e9dd6',
   'DNSName': 'Splunk-syslog-LB-952a4c2f4d4e9dd6.elb.eu-west-1.amazonaws.com',
   'CanonicalHostedZoneId': 'Z2IFOLAFXWLO4F',
   'CreatedTime': datetime.datetime(2018, 2, 12, 15, 11, 7, 467000, tzinfo=tzutc()),
   'LoadBalancerName': 'Splunk-syslog-LB',
   'Scheme': 'internal',
   'VpcId': 'vpc-6f0aad08',
   'State': {'Code': 'active'},
   'Type': 'network',
   'AvailabilityZones': [{'ZoneName': 'eu-west-1a',
     'SubnetId': 'subnet-8bcf64c2',
     'LoadBalancerAddresses': []}],
   'IpAddressType': 'ipv4'},
  {'LoadBalancerArn': 'arn:aws:elasticloadbalancing:eu-west-1:216393279172:loadbalancer/app/UBM-Receiver/bcfdf4811cc2434f',
  """
    client = boto3.client('elbv2', region_name="eu-west-1")
    return client.describe_load_balancers()



def find_all_rds():
    client = boto3.client('rds')
    return client.describe_db_instances()



def find_ec2_sg_assoc(sg_id):
    full_sg_list = []
    for i in find_all_ec2():
        for ec2 in i['Instances']:
            for tags in ec2['Tags']:
                if tags['Key'] == 'Name':
                    ec2_name = tags['Value']
                else:
                    ec2_name = "unknown"
            for sg in ec2['SecurityGroups']:
                if sg_id == sg['GroupId']:
                    full_sg_list.append({
                        "InstanceId": ec2['InstanceId'],
                        "SecurityGroupID": sg['GroupId'],
                        "InstanceName": ec2_name
                    })

    x = [dict(t) for t in {tuple(d.items()) for d in full_sg_list}]
    return x


def find_all_rds_assoc(sg_id):
    rds_sg_map = []
    for db in find_all_rds()['DBInstances']:
        name = db['DBInstanceIdentifier']
        endpoint = db['Endpoint']['Address']
        port = db['Endpoint']['Port']
        for sg in db['VpcSecurityGroups']:
            if sg_id == sg['VpcSecurityGroupId']:
                rds_sg_map.append({
                    "RdsDBIdentifier": name,
                    "RdsDBInstanceId": endpoint,
                    "RdsDbInstancePort": port,
                    "SecurityGroupId": sg['VpcSecurityGroupId']
                })
            
        
        return rds_sg_map

def find_all_elb_assoc(sg_id):
    elb_map = []
    for lb in find_all_elb()['LoadBalancers']:
        name = lb['LoadBalancerName']
        state = lb['State']
        address = lb['DNSName']
        try:
            for sg in lb['SecurityGroups']:
                if sg_id == sg:
                    elb_map.append(
                        {
                            "LbName": name,
                            "LbState": state,
                            "LbAddress": address,
                            "LbSecurityGroup": sg
                        }
                    )
                
        
        except KeyError:
            # We get this cause there is no SG attached
            pass
        
    return elb_map


if args.sg:
    sg_id = args.sg
    ec2_mappings = find_ec2_sg_assoc(sg_id)
    rds_mappings = find_all_rds_assoc(sg_id)
    elb_mappings = find_all_elb_assoc(sg_id)

    if len(ec2_mappings) > 0:
        print(f"We found a total of {len(ec2_mappings)} security group associations")
        print(f"Security Group Associations on EC2 for: {sg_id}")
        pp(ec2_mappings)

    if len(rds_mappings) > 0:
        print(f"Security Group Associations on RDS for: {sg_id}")
        pp(rds_mappings)


    if len(elb_mappings) > 0:
        print(f"Security Group Associations on ELB for: {sg_id}")
        pp(elb_mappings)

else:
    print("Pass in the sg-id with the --sg flag")
```