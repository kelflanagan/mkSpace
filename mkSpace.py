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
    apis = aws.list_apis()
    if apis == None:
        exit()
    if api_name in apis:
        print(
            'API {} exists. Choose a new name or delete this one.'
            .format(api_name)
            )
        exit()

    # let the user know what we're going to do
    tell_user(jo)

    # create role for lambda function
    role_arn = aws.create_role(jo, '/')
    if role_arn == None:
        exit()

    # attach policy
    if not aws.attach_policy(jo):
        exit()

    # get list of current lambda functions
    function_list = aws.list_functions()
    if function_list == None:
        exit()

    # if the function we intend on installing isn't already there install it
    if api_name not in function_list:
        lambda_arn = aws.create_function(jo, role_arn)
        if lambda_arn != None:
            print('Install successful')
        else:
            print('Install failed')
            exit()
    # update code since the function exists
    else:
        lambda_arn = aws.update_function(jo)
        if lambda_arn != None:
            print('Update successful')
        else:
            print('Update failed')
            exit()

    if not aws.create_api(jo['api_json_file']):
        exit()

# delete API and infrastructure
elif sys.argv[1] == 'delete':
    apis = aws.list_apis()
    if apis == None:
        exit()
    if api_name in apis:
        print('Deleteing API {}.'.format(api_name))
        if not aws.delete_api(apis[api_name]):
            exit()

    function_list = aws.list_functions()
    if function_list == None:
        exit()

    if api_name in function_list:
        print('Deleteing Lambda Function {}.'.format(api_name))
        if not aws.delete_function(function_list[api_name]):
            exit()

    if not aws.detach_policy(jo):
        exit()

    if not aws.delete_role(jo):
        exit()

    print('Successfully deleted mySpace service')

# else bad command
else:
    print('usage : mkSpace create | delete')
    exit()

