import base64
import httplib
import json

""" returns a zip file from a github PUBLIC repo.
parameters: filename on github repo is the repository name on 
github repo_owner is the owner of the repo
returns: zip file obtained
"""
def get_zipfile(filename, repo, repo_owner):
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
