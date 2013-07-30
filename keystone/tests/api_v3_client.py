# -*- coding: utf-8 -*-
"""
    Copyright (C) 2013 Kouhei Maeda <mkouhei@palmtb.net>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import requests
import os.path
import json

API_V3 = 'http://localhost:35357/v3'
TIMEOUT = 5.000
VERIFY = False
ADMIN_TOKEN = 'password'

def set_auth_payload(userid=None, password=None, domain_id=None, domain_name=None,
                 project_id=None, project_name=None):
    payload = {'auth': {'identity': {'methods': ['password'],
                                     'password': {'user': {}}}}}
    if userid:
        payload['auth']['identity']['password']['user'] = {'id': userid, 'password': password}
        
    """
    if domain_id:
        payload['auth']['identity']['password']['user']['domain'] = {'id': domain_id}
    elif domain_name:
        payload['auth']['identity']['password']['user']['domain'] = {'name': domain_name}

    if project_id:
        payload['auth']['scope'] = {'project': {'id': project_id}}
    elif project_name:
        payload['auth']['scope'] = {'project': {'name': project_name}}
        """
    if domain_name and project_name:
        payload['auth']['scope'] = {'project': {'domain': {'name': domain_name},
                                                'name': project_name}}
    return payload



def authenticate(userid, password, domain_name=None, project_name=None):
    url = os.path.join(API_V3, 'auth/tokens')
    headers = {'Content-Type': 'application/json'}
    payload = set_auth_payload(userid=userid, password=password, domain_name=domain_name,
                               project_name=project_name)
    r = requests.post(url, headers=headers, data=json.dumps(payload),
                      timeout=TIMEOUT, verify=VERIFY)
    return r


def retrieve_id_by_name(list_json, entry_name, key):
    return [entry.get('id')
            for entry in list_json.get(key)
            if entry.get('name') == entry_name][0]


def create_domain(domain_name):
    url = os.path.join(API_V3, 'domains')
    payload = {'domain': {'description': domain_name,
                          'enabled': True,
                          'name': domain_name}}
    admin_token = ADMIN_TOKEN
    headers = {'Content-Type': 'application/json', 'X-Auth-Token': admin_token}
    r = requests.post(url, headers=headers, data=json.dumps(payload),
                      timeout=TIMEOUT, verify=VERIFY)
    return r

def list_domains():
    url = os.path.join(API_V3, 'domains')
    admin_token = ADMIN_TOKEN
    headers = {'X-Auth-Token': admin_token}
    r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=VERIFY)
    return r.json()


def show_domain(domain_id=None, domain_name=None):
    if domain_name:
        domain_id = retrieve_id_by_name(list_domains(), domain_name, 'domains')
    url = os.path.join(API_V3, 'domains', domain_id)
    admin_token = ADMIN_TOKEN
    headers = {'X-Auth-Token': admin_token}
    r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=VERIFY)
    return r

# not implemented now ?
def delete_domain(domain_id=None, domain_name=None):
    if domain_name:
        domain_id = retrieve_id_by_name(list_domains(), domain_name, 'domains')
    url = os.path.join(API_V3, 'domains', domain_id)
    admin_token = ADMIN_TOKEN
    headers = {'X-Auth-Token': admin_token}
    r = requests.delete(url, headers=headers, timeout=TIMEOUT, verify=VERIFY)
    return r
    
# not implemented now ?
def update_domain(domain_id, enable=True):
    url = os.path.join(API_V3, 'domains', domain_id)
    payload = {'domain': {'description': 'hoge',
                          'enabled': enable,
                          'name': 'hoge',
                          'id': domain_id,
                          'links': {'self': url}}}
    admin_token = ADMIN_TOKEN
    headers = {'Content-Type': 'application/json', 'X-Auth-Token': admin_token}
    r = requests.patch(url, headers=headers, data=json.dumps(payload),
                       timeout=TIMEOUT, verify=VERIFY)
    return r

def create_project(project_name, domain_name=None):
    url = os.path.join(API_V3, 'projects')
    payload = {'project': {'description': project_name,
                          'enabled': True,
                          'name': project_name}}
    if domain_name:
        payload['project']['domain_id'] = retrieve_id_by_name(list_domains(), domain_name, 'domains')
    admin_token = ADMIN_TOKEN
    headers = {'Content-Type': 'application/json', 'X-Auth-Token': admin_token}
    r = requests.post(url, headers=headers, data=json.dumps(payload),
                      timeout=TIMEOUT, verify=VERIFY)
    return r

def list_projects():
    url = os.path.join(API_V3, 'projects')
    admin_token = ADMIN_TOKEN
    headers = {'X-Auth-Token': admin_token}
    r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=VERIFY)
    return r.json()
    
def show_project(project_id=None, project_name=None):
    if project_name:
        project_id = retrieve_id_by_name(list_projects(), project_name, 'projects')
    url = os.path.join(API_V3, 'projects', project_id)
    admin_token = ADMIN_TOKEN
    headers = {'X-Auth-Token': admin_token}
    r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=VERIFY)
    return r

# Not Implemented
def delete_project(project_id=None, project_name=None):
    if project_name:
        project_id = retrieve_id_by_name(list_projects(), project_name, 'projects')
    url = os.path.join(API_V3, 'projects', project_id)
    admin_token = ADMIN_TOKEN
    headers = {'X-Auth-Token': admin_token}
    r = requests.delete(url, headers=headers, timeout=TIMEOUT, verify=VERIFY)
    return r

def create_group(group_name, domain_name=None):
    url = os.path.join(API_V3, 'groups')
    payload = {'project': {'description': group_name,
                          'name': group_name}}
    if domain_name:
        payload['group']['domain_id'] = retrieve_id_by_name(list_domains(), domain_name, 'domains')
    admin_token = ADMIN_TOKEN
    headers = {'Content-Type': 'application/json', 'X-Auth-Token': admin_token}
    r = requests.post(url, headers=headers, data=json.dumps(payload),
                      timeout=TIMEOUT, verify=VERIFY)
    return r
