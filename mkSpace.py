#!/usr/bin/env python

import aws
import httplib
import json
import sys


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


def delete_mySpace(config_json):
    apis = aws.list_apis()
    if apis == None:
        return False
    if config_json['api_name'] in apis:
        print('Deleteing {} API.'.format(config_json['api_name']))
        if not aws.delete_api(apis[config_json['api_name']]):
            return False

    function_list = aws.list_functions()
    if function_list == None:
        return False

    if config_json['api_name'] in function_list:
        print('Deleteing Lambda Function {}.'.format(config_json['api_name']))
        if not aws.delete_function(function_list[config_json['api_name']]):
            return False

    if not aws.detach_policy(config_json):
        return False

    if not aws.delete_role(config_json):
        return False

    return True


def create_mySpace(config_json):
    # make sure we don't recreate our api
    apis = aws.list_apis()
    if apis == None:
        return False
    if config_json['api_name'] in apis:
        print(
            '{} API exists. Choose a new name or delete this one.'
            .format(config_json['api_name'])
            )
        return False

    # let the user know what we're going to do
    tell_user(config_json)

    # create role for lambda function
    role_arn = aws.create_role(config_json, '/')
    if role_arn == None:
        return False

    # attach policy
    if not aws.attach_policy(config_json):
        return False

    # get list of current lambda functions
    function_list = aws.list_functions()
    if function_list == None:
        return False

    # if the function we intend on installing isn't already there install it
    if config_json['api_name'] not in function_list:
        lambda_arn = aws.create_function(config_json, role_arn)
        if lambda_arn == None:
            return False
    else:
        print(
            '{} exists, consider mkSpace update'
            .format(config_json['api_name'])
            )
        return False

    if not aws.create_api(config_json['api_json_file']):
        return False

    return True


def update_mySpace_code(config_json):
    # make sure we don't recreate our api
    apis = aws.list_apis()
    if apis == None:
        return False
    if config_json['api_name'] not in apis:
        print(
            '{} API does not exist. consider mkSpace create'
            .format(config_json['api_name'])
            )
        return False

    # get list of current lambda functions
    function_list = aws.list_functions()
    if function_list == None:
        return False

    # if the function we intend on updating isn't already there return
    if config_json['api_name'] in function_list:
        lambda_arn = aws.update_function(config_json)
        if lambda_arn == None:
            return False

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
    if create_mySpace(jo):
        print('Install successful')
    else:
        print('Install failed')

# update lambda function code
elif sys.argv[1] == 'update':
    if update_mySpace_code(jo):
        print('Update successful')
    else:
        print('Update failed')

# delete API and infrastructure
elif sys.argv[1] == 'delete':
    if delete_mySpace(jo):
        print('Successfully deleted mySpace service')
    else:
        print('Failed to delete mySpace service')

# else bad command
else:
    print('usage : mkSpace create | delete')
    exit()

