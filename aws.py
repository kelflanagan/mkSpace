import boto3
import botocore
import json
import time
import util


""" list_domains() returns a list of existing domain names.
parameters: none
returns: True and a list of existing domains or False on error
"""
def list_domains():
    domain_list = []
    # create client to api gateway
    api = boto3.client('apigateway')
    try:
        response = api.get_domain_names(
            limit=500
            )
    except botocore.exceptions.ClientError as e:
        print "list_domains(): %s" % e
        return False

    for item in response['items']:
        domain_list.append(item['domainName'])

    return True, domain_list


""" add_domain_name() associates a custom domain name and base path
mapping with the an API.
paramters: host_name, api_name, base_path, stage, certificate (crt), 
           key, certificate chain (chain)
returns url to point DNS to on success and None on failure
"""
def add_domain_name(host_name, api_name, base_path, stage, crt, key, chain):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        dn = api.create_domain_name(
            domainName=host_name,
            certificateName=api_name,
            certificateBody=crt,
            certificatePrivateKey=key,
            certificateChain=chain
            )
    except botocore.exceptions.ClientError as e:
        print "add_domain_name(): %s" % e
        return None

    # connect API to domain name and add base_path
    # get API ID
    apis = list_apis()
    if apis == None:
        return None
    if api_name not in apis:
        return None
    api_id = apis[api_name]
    if stage == '':
        try:
            response = api.create_base_path_mapping(
                domainName=host_name,
                basePath=base_path,
                restApiId=api_id
            )
        except botocore.exceptions.ClientError as e:
            print "add_domain_name(): %s" % e
            return None
    else:
        try:
            response = api.create_base_path_mapping(
                domainName=host_name,
                basePath=base_path,
                restApiId=api_id,
                stage=stage
            )
        except botocore.exceptions.ClientError as e:
            print "add_domain_name(): %s" % e
            return None

    return dn['distributionDomainName']


""" delete_domain_name() deletes the custom domain name and associated base 
path mapping.
parameters: domain_name, api_name, base_path
returns: True on success and False on failure
"""
def delete_domain_name(domain_name, api_name, base_path):
    failure = False
    # create client to api gateway
    api = boto3.client('apigateway')

    #delete base path mapping
    try:
        response = api.delete_base_path_mapping(
            domainName=domain_name,
            basePath=base_path
        )
    except botocore.exceptions.ClientError as e:
        print "delete_domain_name(): %s" % e
        print(
            'base_path = {} and domain_name = {}'
            .format(base_path, domain_name)
        )
        failure = True

    # delete custom domain name
    try:
        response = api.delete_domain_name(
            domainName=domain_name
        )
    except botocore.exceptions.ClientError as e:
        print "delete_domain_name(): %s" % e
        print(
            'base_path = {} and domain_name = {}'
            .format(base_path, domain_name)
        )
        failure = True

    if failure:
        return False
    return True


""" list_api_deployments() lists all depluments for an API
paramters: api_id
return: list where each entry is a deployment ID associated with the API
or None on failure
"""
def list_api_deployments(api_id):
    deployment_list = []
    api = boto3.client('apigateway')
    try:
        response = api.get_deployments(
            restApiId=api_id,
            limit=500
        )
    except botocore.exceptions.ClientError as e:
        print "list_api_deployments(): %s" % e
        return None

    if 'items' in response:
        for item in response['items']:
            deployment_list.append(item['id'])
    return deployment_list


""" add_api_deployment() deploys a production instance of the API
parameters: stage_name and api_id
returns: prod_id on success or None on failure
"""
def add_api_deployment(stage_name, api_id):
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


""" delete_api_deployment() deletes all api deployments
parameters: api_name
returns: True on success and False on failure
"""
def delete_api_deployment(api_name, stage_name):
    # get api_id
    apis = list_apis()
    if apis == None:
        return False
    if api_name in apis:
        api_id = apis[api_name]
    else:
        return False

    # get deployment_id
    deployments = list_api_deployments(api_id)
    if deployments == None:
        return False

    # create client to api gateway
    api = boto3.client('apigateway')
    # delete connected stage
    api.delete_stage(
        restApiId=api_id,
        stageName=stage_name
    )

    # delete deployment
    for deployment in deployments:
        try:
            response = api.delete_deployment(
                restApiId=api_id,
                deploymentId=deployment
            )
        except botocore.exceptions.ClientError as e:
            print "delete_api_deplyment(): %s" % e
            return False
    return True


""" make_api creates an API at Amazon AWS API Gateway
parameters: filename contains the template in swagger 2.0 JSON format
returns: API_ID on success or None on failure
"""
def make_api(filename):
    # read file and convert to bytes
    try:
        with open(filename, 'r') as fp:
            f = fp.read()
            b = bytearray(f)
    except IOError:
        print('make_api(): cannot open file')
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
        print "make_api(): %s" % e
        return None
    return response['id']


""" remove_api() deletes an API at Amazon AWS API Gateway
parameters: api_id
returns: True on success and False on failure
"""
def remove_api(api_id):
    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        api.delete_rest_api(
            restApiId=api_id
            )
    except botocore.exceptions.ClientError as e:
        print "remove_api(): %s" % e
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


""" create_lambda_function() creates a role, a policy, attaches the two, and 
creates a lambda function.
parameters: api_name
            lambda_role        - role name that will have policy attached
                                 the policy is defined in mkSpace.cfg file
                                 under the key with name defined by 
                                 lambda_assume_role that currently gives 
                                 apigateway and lambda the right to assume
                                 the role of the user.
            lambda_assume_role - contains the name of the key described above
            lambda_role_policy - contains the name of the policy that will be
                                 attached to the above role.
            lambda_allow_much  - contains the name of the key found in 
                                 mkSpace.cfg. The value of the key is the
                                 policy.
            lambda_zip_file    - contains the zipped version of the lambda
                                 functions code.
            comment_str        - the description of the lambda function
returns: lambda_arn on success and None on failure
"""
def create_lambda_function(api_name, 
                           lambda_role, 
                           lambda_assume_role, 
                           lambda_role_policy, 
                           lambda_allow_much, 
                           lambda_zip_file, 
                           comment_str
                           ):

    # create role for lambda function
    print('  Creating role')
    lambda_role_arn = create_role(
        lambda_role,
        lambda_assume_role
        )
    if lambda_role_arn == None:
        print('    Failed to create role {}'.format(lambda_role))
        return None
    print('    Created role {}'.format(lambda_role))

    # create policy mySpaceAllowMuch for lambda function
    print('  Creating policy')
    allow_much_policy_arn = create_policy(
        lambda_role_policy,
        lambda_allow_much
        )
    if allow_much_policy_arn == None:
        print('    Failed to create policy {}'.format(lambda_role_policy))
        return None
    print('    Created policy {}'.format(lambda_role_policy))

    # attach managed policy to role
    print('  Attaching policy to role')
    success = attach_managed_policy(
        lambda_role,
        allow_much_policy_arn
        )
    if not success:
        print(
            '    Failed to attached policy {} to role {}'
            .format(lambda_role_policy, lambda_role)
            )
        return None
    print(
        '    Attached policy {} to role {}'
        .format(lambda_role_policy, lambda_role)
        )

    print('  Creating function')
    lambda_arn = create_function(
        api_name,
        lambda_role_arn,
        lambda_zip_file,
        comment_str
        )
    if lambda_arn == None:
        print('    Failed to create lambda function {}'.format(api_name))
        return None
    print('    Created lambda function {}'.format(api_name))

    return lambda_arn


""" delete_lambda_function() deletes the policies, roles, and the 
lambda function associated with mySpace.
parameters:
returns:
"""
def delete_lambda_function(api_name):
    failure = False
    print('  Deleting function')
    function_list = list_functions()
    if function_list == None:
        failure = True
    else:
        if api_name in function_list:
            if delete_function(function_list[api_name]):
                print('    Deleted lambda function {}'.format(api_name))
            else:
                failure = True
                print(
                    '    Failed to delete lambda function {}'
                    .format(api_name)
                    )

    # detach policies from roles
    # list local policies
    print('  Detaching policies from roles')
    policy_list = list_policies()
    if policy_list == None:
        failure = True
    else:
        for policy in policy_list:
            if policy.startswith(api_name):
                roles = list_roles_with_attached_policy(policy_list[policy])
                if roles == None:
                    failure = True
                else:
                    for role in roles:
                        if detach_managed_policy(role, roles[role]):
                            print(
                                '    Detached policy {} from role {}'
                                .format(policy, role))
                        else:
                            print(
                                '    Failed to detach policy {} from role {}'
                                .format(policy, role))
            
    # list roles
    print('  Deleting roles')
    role_list = list_roles()
    if role_list == None:
        failure = True
    else:
        for role in role_list:
            if role.startswith(api_name):
                if delete_role(role):
                    print('    Deleted role {}'.format(role))
                else:
                    print('    Failed to delete role {}'.format(role))

    # list local policies
    print('  Deleting policies')
    policy_list = list_policies()
    if policy_list == None:
        failure = True
    else:
        for policy in policy_list:
            if policy.startswith(api_name):
                if delete_policy(policy_list[policy]):
                    print('    Deleted policy {}'.format(policy))
                else:
                    print('    Failed to delete policy {}'.format(policy))
    if failure:
        return False
    return True


""" create_api() creates the roles, policies, reources, and methods
to implement the API.
paramters: config_json, api_json, lambda_arn, and region
returns: API_ID on success, None on failure
"""
def create_api(api_name,
                   api_role,
                   assume_role,
                   api_role_policy,
                   lambda_invoke,
                   api_json_file,
                   lambda_arn,
                   region,
                   stage_name
                   ):
    # create role for API Gateway to invoke lambda functions
    print('  Creating API role')
    api_role_arn = create_role(
        api_role,
        assume_role
        )
    if api_role_arn == None:
        return None
    print('    Created role {}'.format(api_role))

    # create policy mySpaceInvokeLambda for apigateway to 
    # invoke lambda function
    print('  Creating API policy')
    invoke_lambda_policy_arn = create_policy(
        api_role_policy,
        lambda_invoke
        )
    if invoke_lambda_policy_arn == None:
        return None
    print('    Created policy {}'.format(api_role_policy))
    
    # attach managed policy to role
    print('  Attaching policy to role')
    success = attach_managed_policy(
        api_role,
        invoke_lambda_policy_arn
        )
    if not success:
        return None
    print(
        '    Attached policy {} to role {}'.format(api_role_policy, api_role))

    # before the creation of the API we need to modify the API template file
    # things that need to be done
    # 1. uri fields need to point to the lambda function created above
    # 2. credentials field needs to point to role created above
    #
    # form uri value
    api_json = util.get_json_object(api_json_file)
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
    if not util.put_json_object(api_json, api_json_file):
        return None

    # create api
    print('  Creating API')
    api_id = make_api(api_json_file)
    if api_id == None:
        print('    Failed to create {} API'.format(api_name))
        return None
    print('    Created {} API'.format(api_name))

    # deploy API into production (prod)
    print('  Deploying API')
    prod_id = add_api_deployment(
        stage_name,
        api_id
        )
    if prod_id == None:
        print(
            '    Failed to deploy {} version of API {}'
            .format(api_name, stage_name)
            )
        return None

    print('    Deployed {} version of {} API'.format(stage_name, api_name))
    print(
        '    It can be reached at: https://{}.execute-api.{}.amazonaws.com/{}'
        .format(api_id, region, stage_name)
        )

    return api_id


""" delete_api() deletes the deployments, the API, the roles and policies
associated with the API.
parameters: api_name and stage_name
returns: returns True on success and False on failure
"""
def delete_api(api_name, stage_name):
    failure = False
    # delete deployments associated with API
    print('  Deleting deployment')
    success = delete_api_deployment(
        api_name,
        stage_name
        )
    if success:
        print('    Deleted {}'.format(stage_name))
    else:
        print('    Failed to delete {}'.format(stage_name))
        failure = True

    # delete API
    print('  Deleting API')
    apis = list_apis()
    if apis == None:
        failure = True
    else:
        if api_name in apis:
            if remove_api(apis[api_name]):
                print('    Deleted {} API'.format(api_name))
            else:
                failure = True
                print('    Failed to delete {} API'.format(api_name))
        else:
            failure = True
                
    if failure:
        return False
    else:
        return True
