#!/usr/bin/env python

import aws
import github
import httplib
import json
import string
import sys
import time
import util

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


""" is_domain_remnant() checks to see if any parts of a custom domain
remain. If there are remnants True is returned.
paramters: domain_name
returns: True if remnant exists, False if they do not, error returns True
causing us to try again
"""
def is_domain_remnant(domain_name):
    success, list = aws.list_domains()
    if success:
        if domain_name in list:
            return True
        else:
            return False
    else:
        return True


""" delete_mySpace() deletes the role, policy, lambda function
and the API.
parameters: config_json
returns: True on success and False on failure
"""
def delete_mySpace(config_json):
    failure = False
    print('Deleting API -')
    success = aws.delete_api(
        config_json['api_name'],
        config_json['api_name'] + 'Prod',
        )
    if not success:
        failure = True

    print('Deleting lambda function -')
    success = aws.delete_lambda_function(
        config_json['api_name']
        )
    if not success:
        failure = True

    if failure:
        return False
    return True


""" create_mySpace() creates the role, policy, lambda function
and the API.
parameters: config_json
returns: True on success and False on failure
"""
def create_mySpace(config_json, api_json):
    # get function code in zip format from github repo
    print('Downloading lambda function code -')
    success, lambda_zip_file = github.get_zipfile(
        config_json['github_file'], 
        config_json['github_repo'], 
        config_json['github_repo_owner']
        )
    if not success:
        print(
            'Failed to obtain {} from github repo {}'
            .format(
                config_json['github_file'],
                config_json['github_repo']
                )
            )
        return False
    print(
        '  Obtained {} from github repo {}'
        .format(
            config_json['github_file'],
            config_json['github_repo']
            )
        )

    # form description
    description = (
        config_json['api_name']
        + ' is the installer app for the '
        + config_json['api_name']
        + ' services'
        )

    print('Creating lambda function -')
    lambda_arn = aws.create_lambda_function(
        config_json['api_name'],
        config_json['api_name'] + config_json['aws_lambda_role'],
        config_json['aws_assume_role'],
        config_json['api_name'] + config_json['aws_lambda_role_policy'],
        config_json['aws_allow_much'],
        lambda_zip_file,
        description
        )

    # acquire region from lambda arn
    region = string.split(lambda_arn, ':')[3]

    # create API
    print('Creating API -')
    api_id = aws.create_api(
        config_json['api_name'],
        config_json['api_name'] + config_json['aws_api_role'],
        config_json['aws_assume_role'],
        config_json['api_name'] + config_json['aws_api_role_policy'],
        config_json['aws_lambda_invoke'],
        config_json['api_json_file'],
        lambda_arn,
        region,
        config_json['api_name'] + 'Prod'
        )

    if api_id == None:
        print('Failed to create API {}'.format(config_json['api_name']))
        return False
    print(
        'Created API {}'.format(config_json['api_name']))

    return True


""" update_mySpace() updates just the code in an existing lambda 
function.
parameters: config_json
returns: True on success and False on failure
"""
def update_mySpace(config_json):
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
if len(sys.argv) == 1:
    print('usage : mkSpace create | delete | update | domain [options]')
    print('domain options include add | delete')
    exit()

if sys.argv[1] == 'help':
    print('usage : mkSpace create | delete | update | domain [options]')
    print('domain options include add | delete')
    exit()

# get configuration object
config_json = util.get_json_object('mkSpace.cfg')
if config_json == None:
    exit()

# get API config file
api = util.get_json_object(config_json['api_json_file'])
if api == None:
    exit()

# adjust title in API config file
api['info']['title'] = config_json['api_name']

# create API and infrastructure
if sys.argv[1] == 'create':
    if is_api_remnant(config_json['api_name']):
        print(
            '{} API, or a remnant of it, exist. Use mkSpace delete'
            .format(config_json['api_name'])
            )
        exit()

    if create_mySpace(config_json, api):
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

    if update_mySpace(config_json):
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

    if is_domain_remnant(config_json['host_name']):
        print('The domain {} exists'.format(config_json['host_name']))
        print('Use \"mkSpace domain delete\" before deleting the API')
        exit()

    if delete_mySpace(config_json):
        print(
            'Successfully deleted the {} service'
            .format(config_json['api_name'])
            )
    else:
        print(
            'Failed to delete some components of the {} service'
            .format(config_json['api_name'])
            )

# support custom domain names
elif sys.argv[1] == 'domain':
    if len(sys.argv) != 3:
        print('usage : mkSpace domain add | delete')
        exit()

    if not is_api_remnant(config_json['api_name']):
        print(
            '{} API does not exist. Use mkSpace create before mkSpace domain'
            .format(config_json['api_name'])
            )
        exit()

    if sys.argv[2] == 'add':
        # collect certificate, key, and chain
        print('Reading certificate file')
        try:
            with open(config_json['host_name_crt_file'], 'r') as crt_fp:
                crt = crt_fp.read()
        except IOError:
            print("Can't find certificate file")
            exit()
        except:
            print('Unexpected exception getting certificate file')
            exit()

        # collect key
        print('Reading key file')
        try:
            with open(config_json['host_name_key_file'], 'r') as key_fp:
                key = key_fp.read()
        except IOError:
            print("Can't find key file")
            exit()
        except:
            print('Unexpected exception getting key file')
            exit()

        # collect chain
        print('Reading certificate chain file')
        try:
            with open(config_json['crt_chain'], 'r') as chain_fp:
                chain = chain_fp.read()
        except IOError:
            print("Can't find certificate chain file")
            exit()
        except:
            print('Unexpected exception getting certificate chain file')
            exit()

        url = aws.add_domain_name(
            config_json['host_name'],
            config_json['api_name'],
            config_json['api_name'],
            config_json['api_name'] + 'Prod',
            crt, 
            key, 
            chain
            )
        if url != None:
            print('Custom domain successfully added')
            print(
                'Please set the CNAME for {} to {} to complete the setup'
                .format(config_json['host_name'], url)
                )
            print(
                '{} API can be reached at {}/{}'
                .format(
                    config_json['api_name'], 
                    config_json['host_name'], 
                    config_json['api_name']
                    )
                )
        else:
            print('Failed to successfully add custom domain name')
        
    if sys.argv[2] == 'delete':
        success = aws.delete_domain_name(
            config_json['host_name'], 
            config_json['api_name'],
            config_json['api_name']
            )
        if success:
            print('Deleted custom domain name')
        else:
            print('Failed to delete custom domain name')

# else bad command
else:
    print('usage : mkSpace create | delete | update | domain [options]')
    print('domain options include add | delete')
    exit()

