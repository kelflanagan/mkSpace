#!/usr/bin/env python

import aws
import github
import httplib
import json
import string
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

def delete_domain_name(config_json):
    failure = False
    # delete base path mapping
    print('Deleting base path mapping -')
    success = aws.delete_base_path_mapping(
        config_json['host_name'], 
        config_json['api_name']
    )
    if success:
        print(
            'Deleted basepath mapping {}/{}'
            .format(config_json['host_name'], config_json['api_name'])
        )
    else:
        failure = True
        print(
            'Did not delete basepath mapping {}/{}'
            .format(config_json['host_name'], config_json['api_name'])
        )

    # not done
    if failure:
        return False
    return True


""" add_domain_name() associates a custom domain name with the mySpace
API.
paramters: config_json
returns url to point DNS to on success and None on failure
"""
def add_domain_name(config_json):
    # collect certificate
    try:
        with open(config_json['host_name_crt_file'], 'r') as crt_fp:
            crt = crt_fp.read()
    except IOError:
        print('add_domain_name(): no such certificate file')
        return False
    except:
        print('add_domain_name(): unexpected exception')
        return False

    # collect key
    try:
        with open(config_json['host_name_key_file'], 'r') as key_fp:
            key = key_fp.read()
    except IOError:
        print('add_domain_name(): no such key file')
        return False
    except:
        print('add_domain_name(): unexpected exception')
        return False

    # collect chain
    try:
        with open(config_json['crt_chain'], 'r') as chain_fp:
            chain = chain_fp.read()
    except IOError:
        print('add_domain_name(): no such chain file')
        return False
    except:
        print('add_domain_name(): unexpected exception')
        return False

    response = aws.add_domain_name(
        config_json['host_name'],
        config_json['api_name'],
        crt,
        key,
        chain
        )
    if response == None:
        return False

    # connect API to domain name and add base_path
    # get API ID
    apis = aws.list_apis()
    if apis == None:
        return False
    if config_json['api_name'] not in apis:
        return False
    api_id = apis[config_json['api_name']]
    success = aws.add_base_path_mapping(
        config_json['host_name'],
        config_json['api_name'],
        api_id, 
        ''
        )
    if not success:
        return False
        
    print('Custom domain successfully added')
    print(
        'Please set the CNAME for {} to {} to complete the setup'
        .format(config_json['host_name'], response)
        )
    print(
        '{} API can be reached at {}/{}'
        .format(
            config_json['api_name'], 
            config_json['host_name'], 
            config_json['api_name']
            )
        )
    return True


""" delete_mySpace() deletes the role, policy, lambda function
and the API.
parameters: config_json
returns: True on success and False on failure
"""
def delete_mySpace(config_json):
    failure = False
    # delete deployments associated with API
    print('Deleting deployment -')
    success = aws.delete_api_deployment(
        config_json['api_name'],
        config_json['api_name'] + 'Prod'
        )
    if success:
        print(
            'Deleted {}'
            .format(config_json['api_name'] + 'Prod')
            )
    else:
        failure = True
        print(
            'Failed to delete {}'
            .format(config_json['api_name'] + 'Prod')
            )

    # delete API
    print('Deleting API -')
    apis = aws.list_apis()
    if apis == None:
        failure = True
    else:
        if config_json['api_name'] in apis:
            if aws.delete_api(apis[config_json['api_name']]):
                print(
                    'Deleted {} API'.format(config_json['api_name'])
                    )
            else:
                failure = True
                print(
                    'Failed to delete {} API'.format(config_json['api_name'])
                    )

    print('Deleting lambda function -')
    function_list = aws.list_functions()
    if function_list == None:
        failure = True
    else:
        if config_json['api_name'] in function_list:
            if aws.delete_function(function_list[config_json['api_name']]):
                print(
                    'Deleted lambda function {}'
                    .format(config_json['api_name'])
                    )
            else:
                failure = True
                print(
                    'Failed to delete lambda function {}'
                    .format(config_json['api_name'])
                    )

    # detach policies from roles
    # list local policies
    print('Detaching policies from roles -')
    policy_list = aws.list_policies()
    if policy_list == None:
        failure = True
    else:
        for policy in policy_list:
            if policy.startswith(config_json['api_name']):
                roles = aws.list_roles_with_attached_policy(policy_list[policy])
                if roles == None:
                    failure = True
                else:
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
    print('Deleting roles -')
    role_list = aws.list_roles()
    if role_list == None:
        failure = True
    else:
        for role in role_list:
            if role.startswith(config_json['api_name']):
                if aws.delete_role(role):
                    print('Deleted role {}'.format(role))
                else:
                    print('Failed to delete role {}'.format(role))

    # list local policies
    print('Deleting policies -')
    policy_list = aws.list_policies()
    if policy_list == None:
        failure = True
    else:
        for policy in policy_list:
            if policy.startswith(config_json['api_name']):
                if aws.delete_policy(policy_list[policy]):
                    print('Deleted policy {}'.format(policy))
                else:
                    print('Failed to delete policy {}'.format(policy))
    if failure:
        return False
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


""" deploy_api() deploys a prod version of the API
paramters: api_name, api_id, stage_name, and region
returns: prod_id on success, None on failure
"""
def deploy_api(api_name, api_id, stage_name, region):
    # deploy API into production (prod)
    prod_id = aws.add_api_deployment(stage_name, api_id)
    if prod_id == None:
        return None

    print('Deployed {} version of {} API'.format(stage_name, api_name))
    print(
        'It can be reached at: https://{}.execute-api.{}.amazonaws.com/{}'
        .format(api_id, region, stage_name)
        )
    return prod_id


""" create_api() creates the roles, policies, reources, and methods
to implement the API.
paramters: config_json, api_json, lambda_arn, and region
returns: API_ID on success, None on failure
"""
def create_api(config_json, api_json, lambda_arn, region):
    # create role for API Gateway to invoke lambda functions
    api_role_arn = aws.create_role(
        config_json['api_name'] + config_json['aws_api_role'],
        config_json['aws_assume_role']
        )
    if api_role_arn == None:
        return None
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
        return None
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
        return None
    print(
        'Attached policy {} to role {}'
        .format(
            config_json['api_name'] + config_json['aws_api_role_policy'],
            config_json['api_name'] + config_json['aws_api_role']
            )
        )

    # before the creation of the API we need to modify the API template file
    # things that need to be done
    # 1. uri fields need to point to the lambda function created above
    # 2. credentials field needs to point to role created above
    #
    # form uri value
    uri_value = (
        'arn:aws:apigateway:' 
        + region
        + ':lambda:path/2015-03-31/functions/'
        + lambda_arn
        + '/invocations'
        )
    # write value into api object in the uri location for each method
    # also write api_role_arn into the credentials value
    api_gw_int = 'x-amazon-apigateway-integration'
    methods = ['get', 'put', 'post', 'delete']
    for method in methods:
        api_json['paths']['/'][method][api_gw_int]['uri'] = uri_value
        api_json['paths']['/'][method][api_gw_int]['credentials'] = api_role_arn

    # write file to disk to save adjustments
    if not put_json_object(api_json, config_json['api_json_file']):
        return None

    # create api
    api_id = aws.create_api(config_json['api_json_file'])
    if api_id == None:
        return None
    return api_id


""" create_mySpace() creates the role, policy, lambda function
and the API.
parameters: config_json
returns: True on success and False on failure
"""
def create_mySpace(config_json, api_json):
    # create role for lambda function
    print('Creating role -')
    lambda_role_arn = aws.create_role(
        config_json['api_name'] + config_json['aws_lambda_role'],
        config_json['aws_assume_role']
        )
    if lambda_role_arn == None:
        print(
            'Failed to create role {}'
            .format(config_json['api_name'] + config_json['aws_lambda_role'])
            )
        return False
    print(
        'Created role {}'
        .format(config_json['api_name'] + config_json['aws_lambda_role'])
        )

    # create policy mySpaceAllowMuch for lambda function
    print('Creating policy -')
    allow_much_policy_arn = aws.create_policy(
        config_json['api_name'] + config_json['aws_lambda_role_policy'],
        config_json['aws_allow_much']
        )
    if allow_much_policy_arn == None:
        print(
            'Failed to create policy {}'
            .format(
                config_json['api_name'] + config_json['aws_lambda_role_policy']
                )
            )
        return False
    print(
        'Created policy {}'
        .format(config_json['api_name'] + config_json['aws_lambda_role_policy'])
        )

    # attach managed policy to role
    print('Attaching policy to role -')
    success = aws.attach_managed_policy(
        config_json['api_name'] + config_json['aws_lambda_role'],
        allow_much_policy_arn
        )
    if not success:
        print(
            'Failed to attached policy {} to role {}'
            .format(
                config_json['api_name'] + config_json['aws_lambda_role_policy'],
                config_json['api_name'] + config_json['aws_lambda_role']
                )
            )
        return False
    print(
        'Attached policy {} to role {}'
        .format(
            config_json['api_name'] + config_json['aws_lambda_role_policy'],
            config_json['api_name'] + config_json['aws_lambda_role']
            )
        )

    # get function code in zip format from github repo
    print('Downloading lambda function code -')
    success, zip_file = github.get_zipfile(
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
        'Obtained {} from github repo {}'
        .format(
            config_json['github_file'],
            config_json['github_repo']
            )
        )

    # create lambda function
    print('Creating lambda function -')
    comment_str = (
        config_json['api_name']
        + ' is the installer app for the '
        + config_json['api_name']
        + ' services'
        )
    
    lambda_arn = aws.create_function(
        config_json['api_name'],
        lambda_role_arn,
        zip_file,
        'test'
        )
    if lambda_arn == None:
        print(
            'Failed to create lambda function {}'
            .format(config_json['api_name'])
            )
        return False
    print(
        'Created lambda function {}'.format(config_json['api_name'])
        )

    # acquire region from lambda arn
    region = string.split(lambda_arn, ':')[3]

    # create API
    print('Creating API -')
    api_id = create_api(config_json, api_json, lambda_arn, region)
    if api_id == None:
        print(
            'Failed to create API {}'
            .format(config_json['api_name'])
            )
        return False
    print(
        'Created API {}'
        .format(config_json['api_name'])
        )

    # deploy prod version of API
    print('Deploying production version of API -')
    prod_id = deploy_api(
        api_json['info']['title'], 
        api_id, 
        config_json['api_name'] + 'Prod',
        region
    )
    if prod_id == None:
        print(
            'Failed to deploy {} version of API {}'
            .format(config_json['api_name'], config_json['api_name'] + 'Prod')
            )
        return False
    return True


""" update_mySpace_code() updates just the code in an existing lambda 
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

    # determine if custom domain should be created
    # work goes here

    return True


#########
#
# begin here
#
#########
# read command line arguments and give user feedback
if len(sys.argv) == 1:
    print('usage : mkSpace create | delete | update | domain [options]')
    print('domain options include add | delete | update')
    exit()

if sys.argv[1] == 'help':
    print('usage : mkSpace create | delete | update | domain [options]')
    print('domain options include add | delete | update')
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
#if not put_json_object(api, config_json['api_json_file']):
#    exit()

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

# support custom domain names
elif sys.argv[1] == 'domain':
    if len(sys.argv) != 3:
        print('usage : mkSpace domain add | delete | update')
        exit()

    if not is_api_remnant(config_json['api_name']):
        print(
            '{} API does not exist. Use mkSpace create before mkSpace domain'
            .format(config_json['api_name'])
            )
        exit()

    if sys.argv[2] == 'add':
        if add_domain_name(config_json):
            print('Custom domain name added')
        else:
            print('Custom domain name add failed')
        
    if sys.argv[2] == 'delete':
        if delete_domain_name(config_json):
            print('Custom domain name deleted')
        else:
            print('Custom domain name delete failed')
        
    if sys.argv[2] == 'update':
        if add_domain_name(config_json):
            print('Custom domain name updated')
        else:
            print('Custom domain name update failed')

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
        print(
            'Successfully deleted the {} service'
            .format(config_json['api_name'])
            )
    else:
        print(
            'Failed to delete some components of the {} service'
            .format(config_json['api_name'])
            )

# else bad command
else:
    print('usage : mkSpace create | delete | update | domain [options]')
    print('domain options include add | delete | update')
    exit()

