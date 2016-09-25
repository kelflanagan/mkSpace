import boto3
import botocore
import json
import string
import time
import util


####### THIS HAS NOT BEEN TESTED ########
""" verify_email_address() verifies the provided email
parameters: email_address
returns: True and message on success and False and None on failure.
"""
def verify_email_address(email_address):
    # create boto3 client
    ses = boto3.client('ses')

    try:
        ses.verify_email_address(
            EmailAddress=email_address
            )
    except botocore.exceptions.ClientError as e:
        print "verify_email_address(): %s" % e
        return False
    return True
###############


""" subscribe_to_sns_topic() sunscribes a lambda function to a sns topic
paramters: topic_name to subscribe to
           lambda_arn (ARN of lambda to subscribe)
returns: topic ARN on success and None on failure
"""
def subscribe_to_sns_topic(topic_name, lambda_arn):
    topic_list = list_sns_topics()
    if topic_list == None:
        return None

    sns = boto3.client('sns')
    if topic_name not in topic_list:
        return None
    try:
        response = sns.subscribe(
            TopicArn=topic_list[topic_name],
            Protocol='lambda',
            Endpoint=lambda_arn
            )
    except botocore.exceptions.ClientError as e:
        print "subscribe_to_sns_topic(): %s" % e
        return None

    if 'SubscriptionArn' not in response:
        return None

    print(response['SubscriptionArn'])
    return response['SubscriptionArn']


""" update_dynamodb_item() creates or updates an item in the db
parameters: t_name (table name)
            k (primary HASH key)
            kt (key type)
            kv (key value)
            item_name
            item_type
            item_value
returns: True on success and False on failure
"""
def update_dynamodb_item(t_name, k, kt, kv, item_name, item_type, item_value):
    db = boto3.client('dynamodb')
    try:
        response = db.update_item(
            TableName = t_name,
            Key = {
                k : {kt : kv}
                },
            UpdateExpression = (
                'set ' + item_name + ' = :iv'
                ),
            ExpressionAttributeValues = {
                ':iv' : {item_type : item_value}
                }
            )
    except botocore.exceptions.ClientError as e:
        print "update_dynamodb_item(): %s" % e
        return False
    # test for success
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False


""" get_dynamodb_table_status() returns the status of the table identified 
parameters: table_name
returns: None for failure or CREATING|UPDATING|DELETING|ACTIVE
"""
def get_dynamodb_table_status(table_name):
    # create boto3 client
    db = boto3.client('dynamodb')
    try:
        response = db.describe_table(
            TableName=table_name
            )
    except botocore.exceptions.ClientError as e:
        print "get_dynamodb_table_status(): %s" % e
        return None
    
    return response['Table']['TableStatus']


""" get_dynamodb_table_arn() returns the arn for the table identified 
parameters: table_name
returns: Arn if the table exists and None otherwise
"""
def get_dynamodb_table_arn(table_name):
    # create boto3 client
    db = boto3.client('dynamodb')
    try:
        response = db.describe_table(
            TableName=table_name
            )
    except botocore.exceptions.ClientError as e:
        print "get_dynamodb_table_arn(): %s" % e
        return None
    
    return response['Table']['TableArn']


""" list_dynamodb_tables() returns a list of db table names
paramters: no parameters
returns: list of table names
"""
def list_dynamodb_tables():
    table_list = []
    # create boto3 client
    db = boto3.client('dynamodb')

    more_pages = True
    try:
        response = db.list_tables()
    except botocore.exceptions.ClientError as e:
        print "list_dynamodb_tables(): %s" % e
        return None

    while more_pages:
        table_list += response['TableNames']
        if 'LastEvaluatedTableName' in response:
            try:
                response = db.list_tables(
                    ExclusiveStartTableName=response['LastEvaluatedTableName']
                    )
            except botocore.exceptions.ClientError as e:
                print "list_dynamodb_tables(): %s" % e
                return None
        else:
            more_pages = False

    return table_list


""" create_dynamodb_table() creates an empty dynamodb table.
paramters: table_name (the namespaced version of the table name
           primary_key (primary key name, string)
returns: the arn of the created table
"""
def create_dynamodb_table(table_name, primary_key):
    # create boto3 client
    db = boto3.client('dynamodb')
    try:
        response = db.create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': primary_key,
                    'AttributeType': 'S'
                    }
                ],
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': primary_key,
                    'KeyType': 'HASH'
                    }
                ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
                }
            )
    except botocore.exceptions.ClientError as e:
        print "create_dynamodb_table(): %s" % e
        return None
    return response['TableDescription']['TableArn']


""" delete_dynamodb_table(table_name) deletes the identified table
paramters: table_name
returns: True on success and False on failure
"""
def delete_dynamodb_table(table_name):
    # create boto3 client
    db = boto3.client('dynamodb')
    try:
        response = db.delete_table(
            TableName=table_name
            )
    except botocore.exceptions.ClientError as e:
        print "delete_dynamodb_table(): %s" % e
        return False
    return True


""" list_sns_topics() returns a dictionary of topic names and arns.
paramters: no parameters
returns: dictionary where the keys represent topic names and the
assocaited values are their respective AWS ARNs
"""
def list_sns_topics():
    topic_list = {}
    # create boto3 client
    sns = boto3.client('sns')

    more_pages = True
    try:
        response = sns.list_topics()
    except botocore.exceptions.ClientError as e:
        print "list_sns_topics(): %s" % e
        return None

    while more_pages:
        for topic in response['Topics']:
            # acquire topic name from arn
            name = string.split(topic['TopicArn'], ':')[5]
            topic_list[name] = topic['TopicArn']
        if 'NextToken' in response:
            try:
                response = sns.list_topics(
                    NextToken=response['NextToken']
                    )
            except botocore.exceptions.ClientError as e:
                print "list_sns_topics(): %s" % e
                return None
        else:
            more_pages = False

    return topic_list


""" create_sns_topic() creates a topic. If the topic exists its ARN is returned
parameters: topic_name
returns: True and topic_arn on success and False and None on failure
"""
def create_sns_topic(topic_name):
    # create boto3 lambda client
    sns = boto3.client('sns')
    try:
        response = sns.create_topic(
            Name=topic_name
            )
    except botocore.exceptions.ClientError as e:
        print "create_sns_topic(): %s" % e
        return None
    
    return response['TopicArn']


""" delete_sns_topic() deletes a topic and all subscriptions to it. 
parameters: topic_arn
returns: True on success and False on failure
"""
def delete_sns_topic(topic_arn):
    # delete subscriptions associated with this topic
    sns = boto3.client('sns')
    more_pages = True
    try:
        response = sns.list_subscriptions_by_topic(
            TopicArn=topic_arn
            )
    except botocore.exceptions.ClientError as e:
        print "delete_sns_topic(): %s" % e
        return False

    while more_pages:
        for subscription in response['Subscriptions']:
            sns.unsubscribe(
                SubscriptionArn=subscription['SubscriptionArn']
                )
        if 'NextToken' in response:
            try:
                response = sns.list_subscriptions_by_topic(
                    TpoicArn=topic_arn,
                    NextToken=response['NextToken']
                    )
            except botocore.exceptions.ClientError as e:
                print "delete_sns_topic(): %s" % e
                return False
        else:
            more_pages = False

    # delete topic
    try:
        response = sns.delete_topic(
            TopicArn=topic_arn
            )
    except botocore.exceptions.ClientError as e:
        print "delete_sns_topic(): %s" % e
        return False

    return True


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


""" list_api_deployments() lists all deployments for an API
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


""" put_api merges an API definition with an existing API. The new portion
is from a python dictionary representing a JSON formatted swagger object
parameters: api (dictionary object in JSON swagger format)
returns: API_ID on success or None on failure
"""
def put_api(api, api_id):
    # convert dict to byte array
    print('convert dict to bytes')
    b = bytearray(json.dumps(api), "ascii")
    print('done converting dict to bytes')

    # create client to api gateway
    api = boto3.client('apigateway')
    # make request
    try:
        response = api.put_rest_api(
            restApiId=api_id,
            mode='merge',
            failOnWarnings=False,
            body=b
            )
    except botocore.exceptions.ClientError as e:
        print "put_rest_api(): %s" % e
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


""" list_api_resources() lists the resources and their ids
paramters: api_name
returns: dictionary with resource as key and id as value or None
"""
def list_api_resources(api_id):
    resource_list = {}
    api = boto3.client('apigateway')
    more_pages = True
    try:
        response = api.get_resources(
            restApiId=api_id
            )
    except botocore.exceptions.ClientError as e:
        print "list_api_resources(): %s" % e
        return False

    while more_pages:
        for item in response['items']:
            resource_list[item['path']] = item['id']
        if 'position' in response:
            try:
                response = api.get_resources(
                    restApiId=api_id,
                    position=response['position']
                    )
            except botocore.exceptions.ClientError as e:
                print "list_api_resources(): %s" % e
                return False
        else:
            more_pages = False

    return resource_list


""" delete_api_resource() deletes the named resource and associated methods
paramters: api_name
           resource_path
returns: True on success and False on failure
"""
def delete_api_resource(api_name, resource_path):
    # get id of api
    api_list = list_apis()
    if api_name not in api_list:
        return False
    api_id = api_list[api_name]

    api = boto3.client('apigateway')
    # get list of resources in associated with API
    resource_list = list_api_resources(api_id)
    # delete resource
    response = api.delete_resource(
        restApiId=api_id,
        resourceId=resource_list[resource_path]
        )
    return True


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


""" add_sns_permission() adds sufficient permission to the lambda function
so sns can invoke it
paramters: function_arn
returns: True on success and False on failure
"""
def add_sns_permission(arn):
    # create boto3 lambda client
    l = boto3.client('lambda')

    try:
        response = l.add_permission(
            FunctionName=arn,
            StatementId='sns_invoke',
            Action='lambda:invokeFunction',
            Principal='sns.amazonaws.com'
            )
    except botocore.exceptions.ClientError as e:
        print "add_sns_permission(): %s" % e
        return False

    return True


""" create_function creates an aws lambda function. 
The python module is contained in a zip file stored at github.com.
paramters: name, handler, role_arn, zip_file, description and timeout
returns: lambds function ARN
"""
def create_function(name, 
                    handler, 
                    language, 
                    role_arn, 
                    zip_file, 
                    description, 
                    timeout):
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
                Runtime=language,
                Role=role_arn,
                Handler=handler + '.' + handler,
                Code={"ZipFile" : zip_file},
                Description=description,
                Timeout=timeout
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


""" delete_function() deletes a Amazon AWS lambda function
parameters: function arn
returns: True on success and False on failure
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
            runtime            - time in seconds that we permit lambda to run
            timeout            - timeout time for the mySpace lambda function
returns: lambda_arn on success and None on failure
"""
def create_lambda_function(api_name, 
                           lambda_role, 
                           lambda_assume_role, 
                           lambda_role_policy, 
                           lambda_allow_much, 
                           lambda_zip_file, 
                           comment_str,
                           timeout
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
        api_name,
        'python2.7',
        lambda_role_arn,
        lambda_zip_file,
        comment_str,
        timeout
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
                   api_invoke_lambda_policy,
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
        api_invoke_lambda_policy
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
    methods = api_json['paths']['/'].keys()
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
