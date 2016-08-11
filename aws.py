import boto3
import botocore
import json
import time


""" add_base_path_mapping() connects the domain name to the API with a base
path and stage path variable.
parameters: domain_name, base_path, api_id, stage
returns True on success and False on failure
"""
def add_base_path_mapping(domain_name, base_path, api_id, stage):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        response = api.create_base_path_mapping(
            domainName=domain_name,
            basePath=base_path,
            restApiId=api_id,
            stage=stage
            )
    except botocore.exceptions.ClientError as e:
        print "add_base_path_mapping(): %s" % e
        return False
    return True


""" add_domain_name() allows the user to point a custom
domain name at their API. cert and cert_chain are pem formatted.
parameters: domain_name, cert_name, cert, cert_private_key, cert_chain
returns: distribution_domain_name on success and None on failure
"""
def add_domain_name(domain_name, cert_name, cert, cert_private_key, cert_chain):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        response = api.create_domain_name(
            domainName=domain_name,
            certificateName=cert_name,
            certificateBody=cert,
            certificatePrivateKey=cert_private_key,
            certificateChain=cert_chain
            )
    except botocore.exceptions.ClientError as e:
        print "deploy_api(): %s" % e
        return None
    return response['distributionDomainName']


""" deploy_api deploys a production instance of the API
parameters: stage_name and api_id
returns: prod_id on success or None on failure
"""
def deploy_api(stage_name, api_id):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        response = api.create_deployment(
            restApiId=api_id,
            stageName=stage_name
            )
    except botocore.exceptions.ClientError as e:
        print "deploy_api(): %s" % e
        return None
    return response['id']


""" create_api creates an API at Amazon AWS API Gateway
parameters: filename contains the template in swagger 2.0 JSON format
returns: API_ID on success or None on failure
"""
def create_api(filename):
    # read file and convert to bytes
    try:
        with open(filename, 'r') as fp:
            f = fp.read()
            b = bytearray(f)
    except IOError:
        print('create_api(): cannot open file')
        return None
        
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        response = api.import_rest_api(
            failOnWarnings=False,
            body=b
            )
    except botocore.exceptions.ClientError as e:
        print "create_api(): %s" % e
        return None
    return response['id']


""" delete_api() deletes an API at Amazon AWS API Gateway
parameters: api_id
returns: True on success and False on failure
"""
def delete_api(api_id):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        api.delete_rest_api(
            restApiId=api_id
            )
    except botocore.exceptions.ClientError as e:
        print "delete_api(): %s" % e
        return False
    return True


""" list_apis lists all APIs at AWS
paramters: None
return: dictionary where each object has key=api_name and value is api_id 
or None on failure
"""
def list_apis():
    api_list = {}
    api = boto3.client('apigateway')
    try:
        response = api.get_rest_apis(
            limit=500
            )
    except botocore.exceptions.ClientError as e:
        print "list_apis(): %s" % e
        return None

    if 'items' in response:
        for item in response['items']:
            api_list[item['name']] = item['id'] 
    return api_list


""" list the policies and create a dictionary of their names and
associated arn's.
paramters: none
returns: dictionary of policies and their arn's. None on failure
"""
def list_policies():
    policy_list = {}
    iam = boto3.client('iam')
    more_pages = True
    try:
        response = iam.list_policies(
            Scope='Local'
            )
    except botocore.exceptions.ClientError as e:
        print "list_policies(): %s" % e
        return None

    while more_pages:
        for policy in response['Policies']:
            policy_list[policy['PolicyName']] = policy['Arn']
        if response['IsTruncated']:
            try:
                response = iam.list_policies(
                    Marker=response['Marker'],
                    Scope='Local'
                    )
            except botocore.exceptions.ClientError as e:
                print "list_policies(): %s" % e
                return None
        else:
            more_pages = False

    return policy_list


""" list_roles_attached_to_policy() finds roles attached to a policy arn
paramters: policy_arn
returns: dictionary with keys of role names and values of attached policy
"""
def list_roles_with_attached_policy(policy_arn):
    role_list = {}
    # create boto3 iam client
    iam = boto3.client('iam')
    more_pages = True
    try:
        response = iam.list_entities_for_policy(
            PolicyArn=policy_arn
            )
    except botocore.exceptions.ClientError as e:
        print "list_roles_attached_to_policy(): %s" % e
        return None

    while more_pages:
        for role in response['PolicyRoles']:
            role_list[role['RoleName']] = policy_arn
        if response['IsTruncated']:
            try:
                response = iam.list_entities_for_policy(
                    PolicyArn=policy_arn,
                    Marker=response['Marker']
                    )
            except botocore.exceptions.ClientError as e:
                print "list_entities_for_policy(): %s" % e
                return None
        else:
            more_pages = False

    return role_list


""" create_policy() create an aws policy
paramters: policy_name and JSON description of policy
returns: policy ARN on success and None on failure
"""
def create_policy(policy_name, policy):
    # create boto3 iam client
    iam = boto3.client('iam')
    # create policy
    try:
        response = iam.create_policy(
            PolicyName=policy_name,
            Path='/',
            PolicyDocument=json.dumps(policy),
            Description='policy used for mySpace application'
            )
    except botocore.exceptions.ClientError as e:
        print "create_policy(): %s" % e
        return None
    return response['Policy']['Arn']


""" delete_policy() deletes an aws policy
paramters: Arn of policy to remove
returns: True on success and Falae on failure
"""
def delete_policy(policy_arn):
    # create boto3 iam client
    iam = boto3.client('iam')
    # create policy
    try:
        iam.delete_policy(
            PolicyArn=policy_arn
            )
    except botocore.exceptions.ClientError as e:
        print "delete_policy(): %s" % e
        return False
    return True


""" attach_managed_policy() connects policy (policy_arn)
to the named role.
parameters: role_name and policy Arn
returns: True or False
"""
def attach_managed_policy(role_name, policy_arn):
    # create boto3 iam client
    iam = boto3.client('iam')
    # attach policy to the role
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
            )
    except botocore.exceptions.ClientError as e:
        print "attach_managed_policy(): %s" % e
        return False
    return True


""" detach_managed_policy disconnects the policy with an Arn
from the named role.
parameters: role_name and policy Arn
returns: True or False
"""
def detach_managed_policy(role_name, policy_arn):
    # create boto3 iam client
    iam = boto3.client('iam')
    # attach policy to the role
    try:
        iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
            )
    except botocore.exceptions.ClientError as e:
        print "detach_managed_policy(): %s" % e
        return False
    return True


""" create_role() creates a role in aws with a trust policy defined
in the aws JSON format
parameters: role_name and trust_policy
returns: role's arn
"""
def create_role(role_name, trust_policy):
    role_list = list_roles()
    if role_list == None:
        return None
    if role_name in role_list:
        return None

    # create boto3 iam client
    iam = boto3.client('iam')
    # create role
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
    except botocore.exceptions.ClientError as e:
        print "create_role(): %s" % e
        return None
    return response['Role']['Arn']


""" delete_role() deletes the role named in parameter.
parameters: role_name to delete
returns: True on success and False on failure
"""
def delete_role(role_name):
    iam = boto3.client('iam')
    try:
        iam.delete_role(
            RoleName=role_name
            )
    except botocore.exceptions.ClientError as e:
        print "aws_delete_role(): %s" % e
        return False
    return True


""" list_roles() lists the roles at aws and creates a dictionary of 
their names and associated arn's.
paramters: None
returns: dictionary of roles and their arn's. None on failure
"""
def list_roles():
    role_list = {}
    # create boto3 iam client
    iam = boto3.client('iam')

    more_pages = True
    try:
        response = iam.list_roles()
    except botocore.exceptions.ClientError as e:
        print "list_roles(): %s" % e
        return None

    while more_pages:
        for role in response['Roles']:
            role_list[role['RoleName']] = role['Arn']
        if response['IsTruncated']:
            try:
                response = iam.list_roles(
                    Marker=response['Marker']
                    )
            except botocore.exceptions.ClientError as e:
                print "list_roles(): %s" % e
                return None
        else:
            more_pages = False

    return role_list


""" create_function creates an aws lambda function. 
The python module is contained in a zip file stored at github.com.
paramters: cfg_json where the github info is found role_arn to 
attach to this lambda function
returns: lambds function ARN
"""
def create_function(name, role_arn, zip_file, description):
    e = None

    # create boto3 lambda client
    l = boto3.client('lambda')

    # we retry here because the creation of an aws role and attached
    # policy can take several seconds and the create function fails if
    # it is created before the role and policy are in place
    retries = 5
    while retries > 0:
        try:
            response = l.create_function(
                FunctionName=name,
                Runtime='python2.7',
                Role=role_arn,
                Handler=name + '.' + name,
                Code={"ZipFile" : zip_file},
                Description=description
                )
            return response['FunctionArn']
        except botocore.exceptions.ClientError as e:
            retries -= 1
            time.sleep(5)

    print "create_function(): %s" % e
    return None


""" update_function updates the code of an aws lambda function. 
The python module is contained in a zip file stored at github.com.
paramters: cfg_json where the github info is found 
returns: lambds function ARN
"""
def update_function(name, zip_file):
    # create boto3 lambda client
    l = boto3.client('lambda')
    try:
        response = l.update_function_code(
            FunctionName=name,
            ZipFile=zip_file
            )
    except botocore.exceptions.ClientError as e:
        print "update_function(): %s" % e
        return None

    return response['FunctionArn']


""" delete_function() deletes aAmazon AWS lambda function
parameters: function arn
returns: Nothing
"""
def delete_function(function_arn):
    # create client to api gateway
    l = boto3.client('lambda')
    # make request
    try:
        l.delete_function(
            FunctionName=function_arn
            )
    except botocore.exceptions.ClientError as e:
        print "delete_function(): %s" % e
        return False
    return True


""" list the lambda functions and create a dictionary of their names and
associated arn's.
paramters: none
returns: dictionary of functions and their arn's.
"""
def list_functions():
    function_list = {}
    # create boto3 lambda client
    l = boto3.client('lambda')

    more_pages = True
    try:
        response = l.list_functions()
    except botocore.exceptions.ClientError as e:
        print "list_functions(): %s" % e
        return None

    while more_pages:
        for function in response['Functions']:
            function_list[function['FunctionName']] = function['FunctionArn']
        if 'NextMarker' in response:
            try:
                response = l.list_functions(
                    Marker=response['NextMarker']
                    )
            except botocore.exceptions.ClientError as e:
                print "list_functions(): %s" % e
                return None
        else:
            more_pages = False

    return function_list
