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

def set_auth_payload(userid=None, password=None, domain_id=None, domain_name=None,
                 project_id=None, project_name=None):
    payload = {'auth': {'identity': {'methods': ['password'],
                                     'password': {'user': {}}}}}
    if userid:
        payload['auth']['identity']['password']['user'] = {'id': userid, 'password': password}
        
    if domain_id:
        payload['auth']['identity']['password']['user']['domain'] = {'id': domain_id}
    elif domain_name:
        payload['auth']['identity']['password']['user']['domain'] = {'name': domain_name}

    if project_id:
        payload['auth']['scope'] = {'project': {'id': project_id}}
    elif project_name:
        payload['auth']['scope'] = {'project': {'name': project_name}}
    return payload



def authenticate(userid, password, domain_name=None, project_name=None):
    url = os.path.join(API_V3, 'auth/tokens')
    headers = {'Content-Type': 'application/json'}
    payload = set_auth_payload(userid=userid, password=password, domain_name=domain_name,
                               project_name=project_name)
    r = requests.post(url, headers=headers, data=json.dumps(payload),
                      timeout=TIMEOUT, verify=VERIFY)
    return r
