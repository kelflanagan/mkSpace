import boto3
import botocore
import github
import json
import time


""" create_api creates an API at Amazon AWS API Gateway
parameters: filename contains the template in swagger 2.0 JSON format
returns: True or False for success or failure
"""
def create_api(filename):
    # read file and convert to bytes
    try:
        with open(filename, 'r') as fp:
            f = fp.read()
            b = bytearray(f)
    except IOError:
        print('create_api(): cannot open file')
        return False
        
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
        return False
    return True


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


""" attach_policy connects the policy found in the config file 
to the role.
parameters: role_name and cfg_json configuration file.
returns: True or False
"""
def attach_policy(cfg_json):
    # create boto3 iam client
    iam = boto3.client('iam')
    # attach policy to the role
    try:
        iam.put_role_policy(
            RoleName=cfg_json['api_name'] + cfg_json['aws_lambda_role'],
            PolicyName=cfg_json['api_name'] + cfg_json['aws_role_policy'],
            PolicyDocument=json.dumps(cfg_json['aws_policy'])
            )
    except botocore.exceptions.ClientError as e:
        print "attach_policy(): %s" % e
        return False
    return True


""" detach_policy detaches a named policy from a role
parameters: json config file
returns: True or False
"""
def detach_policy(cfg_json):
    role_name = cfg_json['api_name'] + '_allow_lambda_much'
    policy_name = cfg_json['api_name'] + 'AllowLambdaMuch'
    iam = boto3.client('iam')
    try:
        iam.delete_role_policy(
            RoleName=role_name,
            PolicyName=policy_name
            )
    except botocore.exceptions.ClientError as e:
        print "detach_policy(): %s" % e
        return False
    return True


""" create_role creates a role in aws to give lambda functions 
with this role much access to other services. The policies can be 
modified in mySpace.cfg. 
parameters: config file
returns: amaxon resource number (arn)
"""
def create_role(cfg_json, path):
    arn = None
    role_list = list_roles(path)
    if role_list == None:
        return None
    if cfg_json['api_name'] + cfg_json['aws_lambda_role'] in role_list:
        arn = role_list[cfg_json['api_name'] + cfg_json['aws_lambda_role']]

    # create boto3 iam client
    iam = boto3.client('iam')

    # create role if needed
    if arn == None:
        try:
            response = iam.create_role(
                Path=path,
                RoleName=cfg_json['api_name'] + cfg_json['aws_lambda_role'],
                AssumeRolePolicyDocument=json.dumps(cfg_json['trust_policy'])
                )
            arn = response['Role']['Arn']
        except botocore.exceptions.ClientError as e:
            print "create_role(): %s" % e
            return None
    return arn


""" delete_role deletes the role named in parameter.
parameters: role_name to delete
returns: Nothing
"""
def delete_role(cfg_json):
    iam = boto3.client('iam')
    try:
        iam.delete_role(
            RoleName=cfg_json['api_name'] + cfg_json['aws_lambda_role']
            )
    except botocore.exceptions.ClientError as e:
        print "aws_delete_role(): %s" % e
        return False
    return True


""" list_roles lists the roles at aws and create a dictionary of 
their names and associated arn's.
paramters: path
returns: dictionary of roles and their arn's.
"""
def list_roles(path):
    role_list = {}
    # create boto3 iam client
    iam = boto3.client('iam')

    more_pages = True
    try:
        response = iam.list_roles(
            PathPrefix=path
            )
    except botocore.exceptions.ClientError as e:
        print "list_roles(): %s" % e
        return None

    while more_pages:
        for role in response['Roles']:
            role_list[role['RoleName']] = role['Arn']
        if response['IsTruncated']:
            try:
                response = iam.list_roles(
                    PathPrefix=path,
                    Marker=response['Marker'],
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
def create_function(cfg_json, role_arn):
    e = None
    # get zip file from github
    success, zip_file = github.get_zipfile(
        cfg_json['github_file'], 
        cfg_json['github_repo'], 
        cfg_json['github_repo_owner']
        )
    if not success:
        return None

    # create boto3 lambda client
    l = boto3.client('lambda')

    # we retry here because the creation of an aws role and attached
    # policy can take several seconds and the create function fails if
    # it is created before the role and policy are in place
    retries = 3
    while retries > 0:
        try:
            response = l.create_function(
                FunctionName=cfg_json['api_name'],
                Runtime='python2.7',
                Role=role_arn,
                Handler=cfg_json['api_name'] + '.' + cfg_json['api_name'],
                Code={"ZipFile" : zip_file},
                Description='mySpace is the installer app for mySpace services'
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
def update_function(cfg_json):
    # get zip file from github
    success, zip_file = github.get_zipfile(
        cfg_json['github_file'], 
        cfg_json['github_repo'], 
        cfg_json['github_repo_owner']
        )
    if not success:
        return None

    # create boto3 lambda client
    l = boto3.client('lambda')
    try:
        response = l.update_function_code(
            FunctionName=cfg_json['api_name'],
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
        response = l.list_functions(
            MaxItems=2
            )
    except botocore.exceptions.ClientError as e:
        print "list_functions(): %s" % e
        return None

    while more_pages:
        for function in response['Functions']:
            function_list[function['FunctionName']] = function['FunctionArn']
        if 'NextMarker' in response:
            try:
                response = l.list_functions(
                    Marker=response['NextMarker'],
                    MaxItems=2
                    )
            except botocore.exceptions.ClientError as e:
                print "list_functions(): %s" % e
                return None
        else:
            more_pages = False

    return function_list
