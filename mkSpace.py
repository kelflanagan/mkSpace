#!/usr/bin/env python

import boto3
import botocore
import sys
import json
import httplib
import base64
import StringIO

""" open the file given as filename and load it as a json object.
parameters: filename of input json setup file
returns: json object
"""
def get_json_object(filename):
    try:
        with open(filename, 'r') as fp:
            j = json.load(fp)
    except ValueError as e:
        print('Error: ' + str(e))
        return None
    return j


""" open the file given as filename and put JSON object in it.
parameters: filename to write object to, JSON object
returns: True or False
"""
def put_json_object(filename, jo):
    try:
        fp = open(filename, 'w')
    except IOError, e:
        print('Error: ' + str(e))
        return False

    try:
        json.dump(jo, fp)
    except ValueError as e:
        print('Error: ' + str(e))
        return False
    return True


""" create_api() creates an API at Amazon AWS API Gateway
parameters: filename is the name of a file in JSON format
returns: True or False for success or failure
"""
def create_api(filename):
    # open file
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
    print(response)
    return True


def tell_user(config_json):
    jo = config_json

    # give user feedback on whats going to take place
    # given the setup file contents
    print('Creating ' + jo['aws_lambda_name'] + ' API at Amazon AWS')
    print('Also installing lambda function ' + jo['aws_lambda_name'])
    print(
        jo['aws_lambda_name'] 
        + ' will be accessible via https' 
        + '://'
        + jo['host'] 
        + '/'
        + jo['aws_lambda_name'] 
        )
    return True


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


""" create a role in aws to give lambda functions with this role
much access to other services. The policies can be modified in
mySpace.cfg. aws_prefix is used to name space the roles and 
policies.
parameters: config file
returns: amaxon resource number (arn)
"""
def create_aws_role(config_json):
    jo = config_json

    arn = None
    role_list = list_aws_roles()
    if jo['aws_prefix'] + '_allow_lambda_much' in role_list:
        arn = role_list[jo['aws_prefix'] + '_allow_lambda_much']

    # create boto3 iam client
    iam = boto3.client('iam')

    # create role if needed
    if arn == None:
        try:
            response = iam.create_role(
                Path='/',
                RoleName=jo['aws_prefix'] + '_allow_lambda_much',
                AssumeRolePolicyDocument=json.dumps(jo['mySpace_aws_trust'])
                )
            arn = response['Role']['Arn']
        except botocore.exceptions.ClientError as e:
            print "Unexpected error: %s" % e
            return None

    # attach policy to the role
    response = iam.put_role_policy(
        RoleName=jo['aws_prefix'] + '_allow_lambda_much',
        PolicyName=jo['aws_prefix'] + 'AllowLambdaMuch',
        PolicyDocument=json.dumps(jo['mySpace_aws_policy'])
        )

    return arn


def install_lambda_function(config_json, role_arn):
    jo = config_json
    # get zip file from github
    success, zip_file = get_github_zipfile(
        jo['github_file'], 
        jo['github_repo'], 
        jo['github_repo_owner']
        )
    if not success:
        return None

    # create boto3 lambda client
    l = boto3.client('lambda')
    response = l.create_function(
        FunctionName=jo['aws_lambda_name'],
        Runtime='python2.7',
        Role=role_arn,
        Handler=jo['aws_lambda_name'] + '.' + jo['aws_lambda_name'],
        Code={"ZipFile" : zip_file},
        Description='mySpace is the installer app for mySpace services'
        )
    print(response)
    arn = 'need to fix this'
    return arn
        

def update_lambda_function(config_json):
    jo = config_json
    # get zip file from github
    success, zip_file = get_github_zipfile(
        jo['github_file'], 
        jo['github_repo'], 
        jo['github_repo_owner']
        )
    if not success:
        return False

    # create boto3 lambda client
    l = boto3.client('lambda')
    response = l.update_function_code(
        FunctionName=jo['aws_lambda_name'],
        ZipFile=zip_file
        )
    print(response)
    return True


# read command line arguments and give user feedback
if len(sys.argv) > 1:
    print('usage : mkSpace')
    exit()

# get configuration object
jo = get_json_object('mkSpace.cfg')
if jo == None:
    exit()

# let the user know what we're going to do
if not tell_user(jo):
    exit()

# create role for lambda function
role_arn = create_aws_role(jo)
if role_arn == None:
    exit()

# get list of current lambda functions
function_list = list_aws_functions()

# if the function we intend on installing isn't already there install it
if jo['aws_lambda_name'] not in function_list:
    lambda_arn = install_lambda_function(jo, role_arn)
    if lambda_arn != None:
        print('Install successful')
    else:
        print('Install failed')

# update code since the function exists
else:
    if update_lambda_function(jo):
        print('Update successful')
    else:
        print('Update failed')
        
