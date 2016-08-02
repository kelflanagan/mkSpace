#!/usr/bin/env python


import boto3
import botocore
import sys
import json
import httplib
import base64
import time

""" get_json_object opens filename containing JSON and load it as a 
python dictionary.
parameters: filename of JSON file
returns: dictionary - JSON object on success and None on failure
"""
def get_json_object(filename):
    try:
        with open(filename, 'r') as fp:
            j = json.load(fp)
    except ValueError as e:
        print('Error: {}'.format(e))
        return None
    except:
        print('Unknown error')
        return None
    return j


""" put_json_object writes a python dictionary as json file to filename.
parameters: json_object and filename - file is pretty printed
returns True if successful, False otherwise.
"""
def put_json_object(json_object, filename):
    try:
        with open(filename, 'w+') as fp:
            json.dump(json_object, fp, indent=2, separators=(',', ': '))
    except TypeError as e:
        print('Error: {}'.format(e))
        return False
    except:
        print('Unknown error')
        return False
    return True


""" aws_create_api() creates an API at Amazon AWS API Gateway
parameters: filename is the name of a file in swagger 2.0 JSON format
returns: True or False for success or failure
"""
def aws_create_api(filename):
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


""" aws_delete_api() deletes an API at Amazon AWS API Gateway
parameters: api_id
returns: Nothing
"""
def aws_delete_api(api_id):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    api.delete_rest_api(
        restApiId=api_id
        )


""" aws_list_apis lists all APIs at AWS
paramters: None
return: dictionary where each object has key=api_name and value is api_id
"""
def aws_list_apis():
    api_list = {}
    api = boto3.client('apigateway')
    response = api.get_rest_apis(limit=500)
    if 'items' in response:
        for item in response['items']:
            api_list[item['name']] = item['id'] 
    return api_list


""" aws_attach_policy connects the policy found in the config file 
to the role.
parameters: role_name and config_json configuration file.
returns: True or False
"""
def aws_attach_policy(j):
    # create boto3 iam client
    iam = boto3.client('iam')
    # attach policy to the role
    try:
        iam.put_role_policy(
            RoleName=j['api_name'] + j['aws_lambda_role'],
            PolicyName=j['api_name'] + j['aws_role_policy'],
            PolicyDocument=json.dumps(j['aws_policy'])
            )
        return True
    except:
        return False


""" aws_detach_policy detaches a named policy from a role
parameters: json config file
returns: True or False
"""
def aws_detach_policy(config_json):
    role_name = api_name + '_allow_lambda_much'
    policy_name = api_name + 'AllowLambdaMuch'
    iam = boto3.client('iam')
    try:
        iam.delete_role_policy(
            RoleName=role_name,
            PolicyName=policy_name
            )
        return True
    except:
        return False


def aws_is_role(role_name):
    iam = boto3.client('iam')
    response = iam.get_role(
        RoleName=role_name
        )
    return response


""" aws_create_role creates a role in aws to give lambda functions 
with this role much access to other services. The policies can be 
modified in mySpace.cfg. 
parameters: config file
returns: amaxon resource number (arn)
"""
def aws_create_role(j):
    arn = None
    role_list = aws_list_roles()
    if j['api_name'] + j['aws_lambda_role'] in role_list:
        arn = role_list[j['api_name'] + j['aws_lambda_role']]

    # create boto3 iam client
    iam = boto3.client('iam')

    # create role if needed
    if arn == None:
        try:
            response = iam.create_role(
                Path='/',
                RoleName=j['api_name'] + j['aws_lambda_role'],
                AssumeRolePolicyDocument=json.dumps(j['trust_policy'])
                )
            arn = response['Role']['Arn']
        except botocore.exceptions.ClientError as e:
            print "Unexpected error: %s" % e
            return None
    return arn


""" aws_delete_role deletes the role named in parameter.
parameters: role_name to delete
returns: Nothing
"""
def aws_delete_role(j):
    iam = boto3.client('iam')
    try:
        iam.delete_role(RoleName=j['api_name'] + j['aws_lambda_role'])
        return True
    except:
        return False


""" aws_list_roles lists the roles at aws and create a dictionary of 
their names and associated arn's.
paramters: none
returns: dictionary of roles and their arn's.
"""
def aws_list_roles():
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


""" aws_create_function creates an aws lambda function. 
The python module is contained in a zip file stored at github.com.
paramters: config_json where the github info is found 
           role_arn to attach to this lambda function
returns: lambds function ARN
"""
def aws_create_function(config_json, role_arn):
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
    retries = 2
    while retries > 0:
        try:
            response = l.create_function(
                FunctionName=api_name,
                Runtime='python2.7',
                Role=role_arn,
                Handler=config_json['api_name'] + '.' + config_json['api_name'],
                Code={"ZipFile" : zip_file},
                Description='mySpace is the installer app for mySpace services'
                )
            return response['FunctionArn']
        except:
            retries = retries - 1
            time.sleep(5)
    return None


""" aws_update_function updates the code of an aws lambda function. 
The python module is contained in a zip file stored at github.com.
paramters: config_json where the github info is found 
returns: lambds function ARN
"""
def aws_update_function(config_json):
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
        FunctionName=config_json['api_name'],
        ZipFile=zip_file
        )
    return response['FunctionArn']


""" aws_delete_function() deletes aAmazon AWS lambda function
parameters: function arn
returns: Nothing
"""
def aws_delete_function(function_arn):
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
def aws_list_functions():
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


def tell_user(j):
    # give user feedback on whats going to take place
    # given the setup file contents
    print('Creating {} API at Amazon AWS'.format(j['api_name']))
    print('Also installing lambda function {}'.format(j['api_name']))
    print('{} will be accessible via https://{}/{}'.format(
            j['api_name'], 
            j['host_name'], 
            j['api_name']
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

# get API config file
api = get_json_object(jo['api_json_file'])
if api == None:
    exit()

# adjust title in API config file
api_name = jo['api_name']
api['info']['title'] = api_name
if not put_json_object(api, jo['api_json_file']):
    exit()

# create API and infrastructure
if sys.argv[1] == 'create':
    # make sure we don't recreate our api
    if api_name in aws_list_apis():
        print(
            'API {} exists. Choose a new name or delete this one.'
            .format(api_name)
            )
        exit()

    # let the user know what we're going to do
    if not tell_user(jo):
        exit()

    # create role for lambda function
    role_arn = aws_create_role(jo)
    if role_arn == None:
        exit()

    # attach policy
    if not aws_attach_policy(jo):
        exit()

    # get list of current lambda functions
    function_list = aws_list_functions()

    # if the function we intend on installing isn't already there install it
    if api_name not in function_list:
        lambda_arn = aws_create_function(jo, role_arn)
        if lambda_arn != None:
            print('Install successful')
        else:
            print('Install failed')
            exit()

    # update code since the function exists
    else:
        lambda_arn = aws_update_function(jo)
        if lambda_arn != None:
            print('Update successful')
        else:
            print('Update failed')
            exit()

    success = aws_create_api(jo['api_json_file'])

# delete API and infrastructure
elif sys.argv[1] == 'delete':
    apis = aws_list_apis()
    if api_name in apis:
        print('Deleteing API {}.'.format(api_name))
        aws_delete_api(apis[api_name])
    function_list = aws_list_functions()

    if api_name in function_list:
        print('Deleteing Lambda Function {}.'.format(api_name))
        aws_delete_function(function_list[api_name])

    if not aws_detach_policy(jo):
        print('Couldn\'t detach policy')

    if not aws_delete_role(jo):
        print('Couldn\'t delete role')

    print('Successfully deleted mySpace service')

# else bad command
else:
    print('usage : mkSpace create | delete')
    exit()

# now we have lambda arn take these steps
# Step 1 - install API using api.json file as template

# Step 2 - add integrations for RequestTemplate usinf lambda_arn
#          also add credentials role
