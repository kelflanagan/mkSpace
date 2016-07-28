#!/usr/bin/env python


import boto3
import botocore
import sys
import json
import httplib
import base64
import StringIO


# global description of api name
api_name = 'mySpace'


""" open filename containing JSON and load it as a dictionary.
parameters: filename of JSON file
returns: dictionary - JSON object
"""
def get_json_object(filename):
    try:
        with open(filename, 'r') as fp:
            j = json.load(fp)
    except ValueError as e:
        print('Error: {}'.format(e))
        return None
    return j


""" create_aws_api() creates an API at Amazon AWS API Gateway
parameters: filename is the name of a file in swagger 2.0 JSON format
returns: True or False for success or failure
"""
def create_aws_api(filename):
    # read file and convert to bytes
    with open(filename, 'r') as fp:
        f = fp.read()
        b = bytearray(f)

    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    response = api.import_rest_api(
        failOnWarnings=False,
        body=b
        )
    print('this is where I left off')
    return True


""" delete_aws_api() deletes an API at Amazon AWS API Gateway
parameters: api_id
returns: Nothing
"""
def delete_aws_api(api_id):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    api.delete_rest_api(
        restApiId=api_id
        )


""" list all APIs at AWS
paramters: None
return: dictionary where each object has key=api_name and value is api_id
"""
def list_aws_apis():
    api_list = {}
    api = boto3.client('apigateway')
    response = api.get_rest_apis(limit=500)
    if 'items' in response:
        for item in response['items']:
            api_list[item['name']] = item['id'] 
    return api_list


""" create a role in aws to give lambda functions with this role
much access to other services. The policies can be modified in
mySpace.cfg. aws_prefix is used to name space the roles and 
policies.
parameters: config file
returns: amaxon resource number (arn)
"""
def create_aws_role(config_json):
    arn = None
    role_list = list_aws_roles()
    if api_name + '_allow_lambda_much' in role_list:
        arn = role_list[api_name + '_allow_lambda_much']

    # create boto3 iam client
    iam = boto3.client('iam')

    # create role if needed
    if arn == None:
        print('creating new role')
        try:
            response = iam.create_role(
                Path='/',
                RoleName=api_name + '_allow_lambda_much',
                AssumeRolePolicyDocument=json.dumps(config_json['trust_policy'])
                )
            arn = response['Role']['Arn']
        except botocore.exceptions.ClientError as e:
            print "Unexpected error: %s" % e
            return None

    # attach policy to the role
    response = iam.put_role_policy(
        RoleName=api_name + '_allow_lambda_much',
        PolicyName=api_name + 'AllowLambdaMuch',
        PolicyDocument=json.dumps(config_json['aws_policy'])
        )

    print(arn)
    return arn


""" deletes the role named in parameter and its inline policy
parameters: role_name to delete
            policy name of inline policy
returns: Nothing
"""
def delete_aws_role(role_name, policy_name):
    iam = boto3.client('iam')
    iam.delete_role_policy(
        RoleName=role_name,
        PolicyName=policy_name
        )
    iam.delete_role(
        RoleName=role_name
        )


""" list the roles at aws and create a dictionary of their names and
associated arn's.
paramters: none
returns: dictionary of roles and their arn's.
"""
def list_aws_roles():
    role_list = {}
    # create boto3 iam client
    iam = boto3.client('iam')

    more_pages = True
    response = iam.list_roles(PathPrefix = '/')
    while more_pages:
        for role in response['Roles']:
            role_list[role['RoleName']] = role['Arn']
        if response['IsTruncated']:
            response = iam.list_roles(
                PathPrefix='/',
                Marker=response['Marker'],
                )
        else:
            more_pages = False

    return role_list


""" create an aws lambda function. The python module is contained in a zip
file stored at github.com.
paramters: config_json where the github info is found 
           role_arn to attach to this lambda function
returns: lambds function ARN
"""
def create_aws_function(config_json, role_arn):
    # get zip file from github
    success, zip_file = get_github_zipfile(
        config_json['github_file'], 
        config_json['github_repo'], 
        config_json['github_repo_owner']
        )
    if not success:
        return None

    # create boto3 lambda client
    l = boto3.client('lambda')
    response = l.create_function(
        FunctionName=api_name,
        Runtime='python2.7',
        Role=role_arn,
        Handler=api_name + '.' + api_name,
        Code={"ZipFile" : zip_file},
        Description='mySpace is the installer app for mySpace services'
        )
    return response['FunctionArn']
        

""" updates the code of an aws lambda function. The python module is 
contained in a zip file stored at github.com.
paramters: config_json where the github info is found 
returns: lambds function ARN
"""
def update_aws_function(config_json):
    # get zip file from github
    success, zip_file = get_github_zipfile(
        config_json['github_file'], 
        config_json['github_repo'], 
        config_json['github_repo_owner']
        )
    if not success:
        return None

    # create boto3 lambda client
    l = boto3.client('lambda')
    response = l.update_function_code(
        FunctionName=api_name,
        ZipFile=zip_file
        )
    return response['FunctionArn']


""" delete_aws_function() deletes aAmazon AWS lambda function
parameters: function arn
returns: Nothing
"""
def delete_aws_function(function_arn):
    # create client to api gateway
    l = boto3.client('lambda')
    # make request
    l.delete_function(
        FunctionName=function_arn
        )


""" list the lambda functions and create a dictionary of their names and
associated arn's.
paramters: none
returns: dictionary of functions and their arn's.
"""
def list_aws_functions():
    function_list = {}
    # create boto3 lambda client
    l = boto3.client('lambda')

    more_pages = True
    response = l.list_functions(MaxItems=2)
    while more_pages:
        for function in response['Functions']:
            function_list[function['FunctionName']] = function['FunctionArn']
        if 'NextMarker' in response:
            response = l.list_functions(
                Marker=response['NextMarker'],
                MaxItems=2
                )
        else:
            more_pages = False

    return function_list


""" returns a zip file from a github PUBLIC repo.
parameters: filename on github
            repo is the repository name on github
            repo_owner is the owner of the repo
returns: zip file obtained
"""
def get_github_zipfile(filename, repo, repo_owner):
    # form call components and make google call
    host = 'api.github.com'
    body = ''
    path = '/repos/' + repo_owner + '/' + repo + '/contents/' + filename
    method = 'GET'
    # make connection using https
    github = httplib.HTTPSConnection(host)
    # make request
    github.request(
        method,
        path,
        body,
        {"User-Agent" : "mkSpace Application"}
        )
    response = github.getresponse()
    if response.status != 200:
        return False, response.status
    
    ghobj = json.loads(response.read())
    # decode content field of returned object
    zip_file = base64.b64decode(ghobj['content'])

    return True, zip_file


def tell_user(host_name):
    # give user feedback on whats going to take place
    # given the setup file contents
    print('Creating {} API at Amazon AWS'.format(api_name))
    print('Also installing lambda function {}'.format(api_name))
    print('{} will be accessible via https://{}/{}'.format(
            api_name, 
            host_name, 
            api_name
            )
          ) 
    return True


# read command line arguments and give user feedback
if len(sys.argv) != 2 :
    print('usage : mkSpace create | delete')
    exit()

# get configuration object
jo = get_json_object('mkSpace.cfg')
if jo == None:
    exit()

# create API and infrastructure
if sys.argv[1] == 'create':
    # make sure we don't recreate our api
    if api_name in list_aws_apis():
        print(
            'API {} exists. Choose a new name or delete this one.'
            .format(api_name)
            )
        exit()

    # let the user know what we're going to do
    if not tell_user(jo['host']):
        exit()

    # create role for lambda function
    role_arn = create_aws_role(jo)
    if role_arn == None:
        exit()

    # get list of current lambda functions
    function_list = list_aws_functions()

    # if the function we intend on installing isn't already there install it
    if api_name not in function_list:
        lambda_arn = create_aws_function(jo, role_arn)
        if lambda_arn != None:
            print('Install successful')
        else:
            print('Install failed')
            exit()

    # update code since the function exists
    else:
        lambda_arn = update_aws_function(jo)
        if lambda_arn != None:
            print('Update successful')
        else:
            print('Update failed')
            exit()

    success = create_aws_api(jo['api_json_file'])

# delete API and infrastructure
elif sys.argv[1] == 'delete':
    apis = list_aws_apis()
    if api_name in apis:
        print('Deleteing API {}.'.format(api_name))
        delete_aws_api(apis[api_name])
    function_list = list_aws_functions()

    if api_name in function_list:
        print('Deleteing Lambda Function {}.'.format(api_name))
        delete_aws_function(function_list[api_name])

    delete_aws_role(
        api_name + '_allow_lambda_much',
        api_name + 'AllowLambdaMuch'
        )
    
    print('Successfully deleted mySpace service')

# else bad command
else:
    print('usage : mkSpace create | delete')
    exit()

# now we have lambda arn take these steps
# Step 1 - install API using api.json file as template

# Step 2 - add integrations for RequestTemplate usinf lambda_arn
#          also add credentials role
