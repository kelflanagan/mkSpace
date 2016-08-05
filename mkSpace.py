#!/usr/bin/env python

import aws
import github
import httplib
import json
import sys
import time

""" get_json_object opens a file containing JSON and loads it as a 
python dictionary.
parameters: filename of JSON file
returns: dictionary - JSON object on success and None on failure
"""
def get_json_object(filename):
    try:
        with open(filename, 'r') as fp:
            j = json.load(fp)
    except ValueError:
        print('get_json_object(): malformed JSON')
        return None
    except IOError:
        print('get_json_object(): no such file')
        return None
    except:
        print('get_json_object(): unexpected exception')
        return None

    return j


""" put_json_object writes a python dictionary as JSON filename.
parameters: json_object and filename - file is pretty printed
returns: True if successful, False otherwise.
"""
def put_json_object(json_object, filename):
    try:
        with open(filename, 'w+') as fp:
            json.dump(json_object, fp, indent=2, separators=(',', ': '))
    except IOError:
        print('put_json_object(): cannot write file')
        return False
    except:
        print('put_json_object(): unexpected exception')
        return False
    return True


""" inform the user of action to be taken """
def tell_user(cfg_json):
    # give user feedback on whats going to take place
    # given the setup file contents
    print('Creating {} API at Amazon AWS'.format(cfg_json['api_name']))
    print('Also installing lambda function {}'.format(cfg_json['api_name']))
    print('{} will be accessible via https://{}/{}'.format(
            cfg_json['api_name'], 
            cfg_json['host_name'], 
            cfg_json['api_name']
            )
          ) 


""" delete_mySpace() deletes the role, policy, lambda function
and the API.
parameters: config_json
returns: True on success and False on failure
"""
def delete_mySpace(config_json):
    apis = aws.list_apis()
    if apis == None:
        return False
    if config_json['api_name'] in apis:
        if aws.delete_api(apis[config_json['api_name']]):
            print('Deleted {} API.'.format(config_json['api_name']))
        else:
            print('Failed to delete {} API.'.format(config_json['api_name']))

    function_list = aws.list_functions()
    if function_list == None:
        return False

    if config_json['api_name'] in function_list:
        if aws.delete_function(function_list[config_json['api_name']]):
            print('Deleted Lambda Function {}.'.format(config_json['api_name']))
        else:
            print(
                'Failed to delete Lambda Function {}.'
                .format(config_json['api_name'])
                )

    # detach policies from roles
    # list local policies
    policy_list = aws.list_policies()
    if policy_list == None:
        return False
    # detach them
    for policy in policy_list:
        if policy.startswith(config_json['api_name']):
            roles = aws.list_roles_with_attached_policy(policy_list[policy])
            if roles == None:
                return False
            for role in roles:
                if aws.detach_managed_policy(role, roles[role]):
                    print(
                        'Detached policy {} from role {}'
                        .format(policy, role))
                else:
                    print(
                        'Failed to detach policy {} from role {}'
                        .format(policy, role))
            
    # list roles
    role_list = aws.list_roles()
    if role_list == None:
        return False
    # delete them
    for role in role_list:
        if role.startswith(config_json['api_name']):
            if aws.delete_role(role):
                print('Deleted role {}'.format(role))
            else:
                print('Failed to delete role {}'.format(role))

    # list local policies
    policy_list = aws.list_policies()
    if policy_list == None:
        return False
    # delete them
    for policy in policy_list:
        if policy.startswith(config_json['api_name']):
            if aws.delete_policy(policy_list[policy]):
                print('Deleted policy {}'.format(policy))
            else:
                print('Failed to delete policy {}'.format(policy))

    return True


""" is_api_remnants() checks to see if any parts of an installation 
remain. If there are remnants True is returned.
paramters: api_name
returns: True if remnanats exist, False if they do not, and None on error
"""
def is_api_remnant(api_name):
    # check for API Gateway pieces
    apis = aws.list_apis()
    if apis == None:
        return None
    if api_name in apis:
        return True

    # check for roles
    roles = aws.list_roles()
    if roles == None:
        return None
    for role in roles:
        if role.startswith(api_name):
            return True
        
    # check for policies
    policies = aws.list_policies()
    if policies == None:
        return None
    for policy in policies:
        if policy.startswith(api_name):
            return True

    # check for lambda functions
    function_list = aws.list_functions()
    if function_list == None:
        return None

    for function in function_list:
        if function.startswith(api_name):
            return True

    return False
    

""" create_mySpace() creates the role, policy, lambda function
and the API.
parameters: config_json
returns: True on success and False on failure
"""
def create_mySpace(config_json):
    # create role for lambda function
    lambda_role_arn = aws.create_role(
        config_json['api_name'] + config_json['aws_lambda_role'],
        config_json['aws_assume_role']
        )
    if lambda_role_arn == None:
        return False
    print(
        'Created role {}'
        .format(config_json['api_name'] + config_json['aws_lambda_role'])
        )

    # create policy mySpaceAllowMuch for lambda function
    allow_much_policy_arn = aws.create_policy(
        config_json['api_name'] + config_json['aws_lambda_role_policy'],
        config_json['aws_allow_much']
        )
    if allow_much_policy_arn == None:
        return False
    print(
        'Created policy {}'
        .format(config_json['api_name'] + config_json['aws_lambda_role_policy'])
        )

    # attach managed policy to role
    success = aws.attach_managed_policy(
        config_json['api_name'] + config_json['aws_lambda_role'],
        allow_much_policy_arn
        )
    if not success:
        return False
    print(
        'Attached policy {} to role {}'
        .format(
            config_json['api_name'] + config_json['aws_lambda_role_policy'],
            config_json['api_name'] + config_json['aws_lambda_role']
            )
        )

    # get function code in zip format from github repo
    success, zip_file = github.get_zipfile(
        config_json['github_file'], 
        config_json['github_repo'], 
        config_json['github_repo_owner']
        )
    if not success:
        return False
    print(
        'Obtained {} from github repo {}'
        .format(
            config_json['github_file'],
            config_json['github_repo']
            )
        )

    lambda_arn = aws.create_function(
        config_json['api_name'],
        lambda_role_arn,
        zip_file,
        'mySpace is the installer app for mySpace services'
        )
    if lambda_arn == None:
        return False
    print('Created lambda function {}'.format(config_json['api_name']))

    # create role for API Gateway to invoke lambda functions
    api_role_arn = aws.create_role(
        config_json['api_name'] + config_json['aws_api_role'],
        config_json['aws_assume_role']
        )
    if lambda_role_arn == None:
        return False
    print(
        'Created role {}'
        .format(config_json['api_name'] + config_json['aws_api_role'])
        )

    # create policy mySpaceInvokeLambda for apigateway to 
    # invoke lambda function
    invoke_lambda_policy_arn = aws.create_policy(
        config_json['api_name'] + config_json['aws_api_role_policy'],
        config_json['aws_lambda_invoke']
        )
    if invoke_lambda_policy_arn == None:
        return False
    print(
        'Created policy {}'
        .format(config_json['api_name'] + config_json['aws_api_role_policy'])
        )
    
    # attach managed policy to role
    success = aws.attach_managed_policy(
        config_json['api_name'] + config_json['aws_api_role'],
        invoke_lambda_policy_arn
        )
    if not success:
        return False
    print(
        'Attached policy {} to role {}'
        .format(
            config_json['api_name'] + config_json['aws_api_role_policy'],
            config_json['api_name'] + config_json['aws_api_role']
            )
        )

    if not aws.create_api(config_json['api_json_file']):
        return False
    print(
        'Created API {}'
        .format(config_json['api_name'])
        )

    return True


""" update_mySpace_cod() updates just the code in an existing lambda 
function.
parameters: config_json
returns: True on success and False on failure
"""
def update_mySpace_code(config_json):
    # get function code in zip format from github repo
    success, zip_file = github.get_zipfile(
        config_json['github_file'], 
        config_json['github_repo'], 
        config_json['github_repo_owner']
        )
    if not success:
        return False
    print(
        'Obtained {} from github repo {}'
        .format(
            config_json['github_file'],
            config_json['github_repo']
            )
        )

    lambda_arn = aws.update_function(
        config_json['api_name'],
        zip_file
        )
    if lambda_arn == None:
        return False
    print(
        'Updated code for lambda function {}'
        .format(config_json['api_name'])
        )

    return True


#########
#
# begin here
#
#########
# read command line arguments and give user feedback
if len(sys.argv) != 2 :
    print('usage : mkSpace create | delete')
    exit()

# get configuration object
config_json = get_json_object('mkSpace.cfg')
if config_json == None:
    exit()

# get API config file
api = get_json_object(config_json['api_json_file'])
if api == None:
    exit()

# adjust title in API config file
api['info']['title'] = config_json['api_name']
if not put_json_object(api, config_json['api_json_file']):
    exit()

# create API and infrastructure
if sys.argv[1] == 'create':
    if is_api_remnant(config_json['api_name']):
        print(
            '{} API, or a remnant of it, exist. Use mkSpace delete'
            .format(config_json['api_name'])
            )
        exit()

    if create_mySpace(config_json):
        print('Install successful')
    else:
        print('Install failed')

# update lambda function code
elif sys.argv[1] == 'update':
    if not is_api_remnant(config_json['api_name']):
        print(
            '{} API does not exist. Use mkSpace create'
            .format(config_json['api_name'])
            )
        exit()

    if update_mySpace_code(config_json):
        print('Update successful')
    else:
        print('Update failed')

# delete API and infrastructure
elif sys.argv[1] == 'delete':
    if not is_api_remnant(config_json['api_name']):
        print(
            '{} API does not exist. Use mkSpace create'
            .format(config_json['api_name'])
            )
        exit()

    if delete_mySpace(config_json):
        print('Successfully deleted mySpace service')
    else:
        print('Failed to delete mySpace service')

# else bad command
else:
    print('usage : mkSpace create | delete')
    exit()

