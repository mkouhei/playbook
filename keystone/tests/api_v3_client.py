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
import ldap

TIMEOUT = 5.000


def set_auth_payload(userid=None, password=None, domain_id=None,
                     domain_name=None, project_id=None, project_name=None):
    payload = {'auth': {'identity': {'methods': ['password'],
                                     'password': {'user': {}}}}}
    if userid:
        payload['auth']['identity']['password']['user'] = {'id': userid,
                                                           'password': password}
    if domain_name and project_name:
        payload['auth']['scope'] = {'project': {'domain': {'name': domain_name},
                                                'name': project_name}}
    elif domain_name and project_id:
        payload['auth']['scope'] = {'project': {'domain': {'name': domain_name},
                                                'id': project_id}}
    elif domain_id and project_name:
        payload['auth']['scope'] = {'project': {'domain': {'id': domain_id},
                                                'name': project_name}}
    elif domain_id and project_id:
        payload['auth']['scope'] = {'project': {'domain': {'id': domain_id},
                                                'id': project_id}}
    elif domain_id and not (project_name and project_id):
        payload['auth']['identity']['password']['user']['domain'] = {'id': domain_id}
    elif domain_name and not (project_name and project_id):
        payload['auth']['identity']['password']['user']['domain'] = {'name': domain_name}
    elif project_id and not (domain_name and domain_id):
        payload['auth']['scope'] = {'project': {'id': project_id}}
    elif project_name and (not domain_name and not domain_id):
        payload['auth']['scope'] = {'project': {'name': project_name}}

    return payload


def retrieve_id_by_name(list_json, entry_name, key):
    """retrieve id by name

    Arguments:
        list_json:
        entry_name:
        key:
    """
    return [entry.get('id')
            for entry in list_json.get(key)
            if entry.get('name') == entry_name][0]


def retrieve_id_by_type(list_json, entry_type, key):
    """retrieve id by type

    Arguments:
        list_json:
        entry_type:
        key:
    """
    return [entry.get('id')
            for entry in list_json.get(key)
            if entry.get('type') == entry_type][0]


class LdapClient(object):
    
    def __init__(self, ldap_url, search_base, binddn, bindpw):
        """initialize variable

        Arguments:
            base_url:
            admin_token:
            verify:
        """
        self.conn = ldap.initialize(ldap_url)
        method = ldap.AUTH_SIMPLE
        self.search_scope = ldap.SCOPE_SUBTREE
        self.search_base = search_base
        try:
            self.conn.bind(binddn, bindpw, method)
        except ldap.SERVER_DOWN as e:
            print(e)

    def search_entry(self, search_word, target):
        if search_word:
            search_filter = '(ou=%s)' % search_word
        if target:
            search_base = 'ou=%s,dc=auth,%s' % (target, self.search_base)
        return  self.conn.search_s(search_base,
                                   self.search_scope,
                                   search_filter)

    def delete_entry(self, search_word, target):
        return self.conn.delete_s(self.search_entry(search_word, target)[0][0])


class ApiV3Client(object):

    def __init__(self, base_url, admin_token, region, verify=True):
        """initialize variable

        Arguments:
            base_url:
            admin_token:
            verify:
        """
        self.base_url = base_url
        self.admin_token = admin_token
        self.verify = verify
        self.region = region

    def _set_api_url(self, *kwards):
        """return api url

        Arguments:
            *kwards:
        """
        url = self.base_url
        for i in kwards:
            url = os.path.join(url, i)
        return url

    def _set_api_url_with_tuple(self, kwards):
        """return api url

        Arguments:
            *kwards:
        """
        url = self.base_url
        for i in kwards:
            url = os.path.join(url, i)
        return url

    def authenticate(self, userid, password, domain_name=None, project_name=None):
        """Authenticate

        Arguments:
            userid:
            password:
            domain_name:
            project_name:
        """
        url = self._set_api_url('auth/tokens')
        headers = {'Content-Type': 'application/json'}
        payload = set_auth_payload(userid=userid,
                                   password=password,
                                   domain_name=domain_name,
                                   project_name=project_name)
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def create_service(self, service_type):
        """create service

        Arguments:
            service_type:

        """
        url = self._set_api_url('services')
        headers = {'X-Auth-Token': self.admin_token, 'Content-Type': 'application/json'}
        payload = {'service': {'type': service_type}}
        services = [service for service in self.list_target('services').get('services')
                    if service.get('type') == service_type]
        if services:
            return None
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def create_endpoint(self, interface, endpoint_name, endpoint_url, service_type):
        """create endpoint

        Arguments:
            interface:     [admin|public|internal]
            endpoint_name:
            endpoint_url:
            service_type:

        """
        url = self._set_api_url('endpoints')
        headers = {'X-Auth-Token': self.admin_token, 'Content-Type': 'application/json'}
        res = self.show_target('services', target_type=service_type).json()
        service_id = res.get('service').get('id')
        payload = {'endpoint': {'name': endpoint_name,
                                'url': endpoint_url,
                                'interface': interface,
                                'region': self.region,
                                'service_id': service_id}}
        endpoints = [endpoint for endpoint in self.list_target('endpoints').get('endpoints')
                     if endpoint.get('name') == endpoint_name]
        print endpoints
        if endpoints:
            return None
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def create_role(self, role_name):
        """create role

        Arguments:
            role_name:

        """
        url = self._set_api_url('roles')
        headers = {'X-Auth-Token': self.admin_token, 'Content-Type': 'application/json'}
        payload = {'role': {'name': role_name}}
        roles = [role for role in self.list_target('roles').get('roles')
                 if role.get('name') == role_name]
        if roles:
            return None
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def list_target(self, *target):
        """list organizationalUnit"""
        url = self._set_api_url_with_tuple(target)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=self.verify)
        return r.json()

    def show_target(self, target, target_id=None, target_name=None, target_type=None):
        """show target

        Arguments:
            target:
            target_id:
            target_name:
            target_type:

        """
        if target_type:
            target_id = retrieve_id_by_type(self.list_target(target), target_type, target)
        elif target_name:
            target_id = retrieve_id_by_name(self.list_target(target), target_name, target)
        url = self._set_api_url(target, target_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=self.verify)
        return r

    def delete_target(self, target, target_id=None, target_name=None, target_type=None):
        """delete target

        Arguments:
            target:
            target_id:
            target_name:

        """
        if target_type:
            target_id = retrieve_id_by_type(self.list_target(target), target_type, target)
        elif target_name:
            target_id = retrieve_id_by_name(self.list_target(target), target_name, target)
        url = self._set_api_url(target, target_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.delete(url, headers=headers, timeout=TIMEOUT, verify=self.verify)
        return r

    def create_domain(self, domain_name):
        """Create domain

        Argument:
            domain_name:
        """
        url = self._set_api_url('domains')
        payload = {'domain': {'description': domain_name,
                              'enabled': True,
                              'name': domain_name}}
        headers = {'Content-Type': 'application/json',
                   'X-Auth-Token': self.admin_token}
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r


    # not implemented now
    def delete_domain(self, domain_id=None, domain_name=None):
        """delete domain

        Arguments:
            domain_id:
            domain_name:
        """
        if domain_name:
            domain_id = retrieve_id_by_name(list_target('domains'), domain_name, 'domains')
        """
        url = self._set_api_url('domains', domain_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.delete(url, headers=headers, timeout=TIMEOUT, verify=self.verify)
        return r
        """
        
    
    # not implemented now ?
    def update_domain(self, domain_id, domain_name, enable=True, description=None,):
        """update domain

        Arguments:
            domain_id:
            domain_name:
            enable:
            description:
        """
        url = self._set_api_url('domains', domain_id)
        payload = {'domain': {'description': description,
                              'enabled': enable,
                              'name': domain_name,
                              'id': domain_id,
                              'links': {'self': url}}}
        headers = {'Content-Type': 'application/json', 'X-Auth-Token': self.admin_token}
        r = requests.patch(url, headers=headers, data=json.dumps(payload),
                           timeout=TIMEOUT, verify=self.verify)
        return r

    def create_project(self, project_name, domain_name=None):
        """create project

        Arguments:
            project_name:
            domain_name:
        """
        url = self._set_api_url('projects')
        payload = {'project': {'description': project_name,
                               'enabled': True,
                               'name': project_name}}
        if domain_name:
            payload['project']['domain_id'] = retrieve_id_by_name(self.list_target('domains'), domain_name, 'domains')
        headers = {'Content-Type': 'application/json', 'X-Auth-Token': self.admin_token}
        print(payload)
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    # Not Implemented
    def delete_project(self, project_id=None, project_name=None):
        """delete project

        Arguments:
            project_id:
            project_name:
        """
        if project_name:
            project_id = retrieve_id_by_name(self.list_target('projects'), project_name, 'projects')
        url = self._set_api_url('projects', project_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.delete(url, headers=headers, timeout=TIMEOUT, verify=self.verify)
        return r

    def create_group(self, group_name, domain_name=None):
        """create group

        Arguments:
            group_name:
            domain_name:
        """
        url = self._set_api_url('groups')
        payload = {'group': {'description': group_name,
                               'name': group_name}}
        if domain_name:
            payload['group']['domain_id'] = retrieve_id_by_name(self.list_target('domains'),
                                                                domain_name,
                                                                'domains')
        headers = {'Content-Type': 'application/json', 'X-Auth-Token': self.admin_token}
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def delete_group(self, group_id=None, group_name=None):
        """delete group

        Arguments:
            group_id:
            group_name:
        """
        if group_name:
            group_id = retrieve_id_by_name(self.list_target('groups'), group_name, 'groups')
        url = self._set_api_url('groups', group_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.delete(url, headers=headers, timeout=TIMEOUT, verify=self.verify)
        return r

    def _get(self, url):
        """show domain

        Arguments:
            url:
        """
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers, timeout=TIMEOUT, verify=self.verify)
        return r
