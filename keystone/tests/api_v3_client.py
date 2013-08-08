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
        payload['auth']['identity']['password']['user'] = {
            'id': userid,
            'password': password}
    if domain_name and project_name:
        payload['auth']['scope'] = {
            'project': {'domain': {'name': domain_name},
                        'name': project_name}}
    elif domain_name and project_id:
        payload['auth']['scope'] = {
            'project': {'domain': {'name': domain_name},
                        'id': project_id}}
    elif domain_id and project_name:
        payload['auth']['scope'] = {
            'project': {'domain': {'id': domain_id},
                        'name': project_name}}
    elif domain_id and project_id:
        payload['auth']['scope'] = {
            'project': {'domain': {'id': domain_id},
                        'id': project_id}}
    elif domain_id and not (project_name and project_id):
        payload['auth']['identity']['password']['user']['domain'] = {
            'id': domain_id}
    elif domain_name and not (project_name and project_id):
        payload['auth']['identity']['password']['user']['domain'] = {
            'name': domain_name}
    elif project_id and not (domain_name and domain_id):
        payload['auth']['scope'] = {'project': {'id': project_id}}
    elif project_name and (not domain_name and not domain_id):
        payload['auth']['scope'] = {'project': {'name': project_name}}

    return payload


def retrieve_id_by_name(list_json, entry_name, key):
    """retrieve id by name, for except services

    Arguments:
        list_json:
        entry_name:
        key:
    """
    return [entry.get('id')
            for entry in list_json.get(key)
            if entry.get('name') == entry_name][0]


def retrieve_id_by_type(list_json, entry_type, key):
    """retrieve id by type, for services

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
        return self.conn.search_s(search_base,
                                  self.search_scope,
                                  search_filter)

    def delete_entry(self, search_word, target):
        return self.conn.delete_s(self.search_entry(search_word, target)[0][0])


def _list(func):
    """list organizationalUnit"""
    def list_objects(self, *args):
        target = (func.func_name.split('list_')[1],)
        if args:
            target += args
        url = self._set_api_url_with_tuple(target)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r.json()
    return list_objects


def _show(func):
    """show target"""
    def show_object(self, target_id=None, target_name=None, target_type=None):
        """

        Arguments:
            target_id:
            target_name:
            target_type:

        """
        target = func.func_name.split('show_')[1]
        if target_type:
            target_id = retrieve_id_by_type(self.list_target(target),
                                            target_type, target)
        elif target_name:
            target_id = retrieve_id_by_name(self.list_target(target),
                                            target_name, target)
        url = self._set_api_url(target, target_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r
    return show_object


def _delete(func):
    """delete target"""
    def delete_object(self, target_id=None,
                      target_name=None, target_type=None):
        """

        Arguments:
            target:
            target_id:
            target_name:

        """
        target = func.func_name.split('delete_')[1]
        if target_type:
            target_id = retrieve_id_by_type(self.list_target(target),
                                            target_type, target)
        elif target_name:
            target_id = retrieve_id_by_name(self.list_target(target),
                                            target_name, target)
        url = self._set_api_url(target, target_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.delete(url, headers=headers,
                            timeout=TIMEOUT, verify=self.verify)
        return r
    return delete_object


def _grant_role(func):
    """grant role to <user|group> on <domain|project>"""
    def grant_role(self, role_id=None, role_name=None,
                   target_id=None, target_name=None,
                   ou_id=None, ou_name=None):
        """

        Arguments:
            target_id:
            target_name:
            ou_id:
            ou_name:

        """
        target = func.func_name.split('grant_role_')[1].split('_')[0] + 's'
        if target_name:
            target_id = retrieve_id_by_name(self.list_target(target),
                                            target_name, target)
        ou_target = func.func_name.split('_on_')[1] + 's'
        if ou_name:
            ou_id = retrieve_id_by_name(self.list_target(ou_target),
                                        ou_name, ou_target)
        if role_name:
            role_id = retrieve_id_by_name(self.list_target('roles'),
                                          role_name, 'roles')

        url = self._set_api_url(ou_target, ou_id,
                                target, target_id,
                                'roles', role_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.put(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r
    return grant_role


def _update(func):
    def update_object(self, target_id=None, target_name=None,
                      target_type=None, payload=None):
        target = func.func_name.split('update_')[1]
        if target_type:
            target_id = retrieve_id_by_type(self.list_target(target),
                                            target_type, target)
        elif target_name:
            target_id = retrieve_id_by_name(self.list_target(target),
                                            target_name, target)
        url = self._set_api_url(target, target_id)
        print url
        headers = {'X-Auth-Token': self.admin_token,
                   'Content-Type': 'application/json'}
        r = requests.patch(url, headers=headers, data=json.dumps(payload),
                           timeout=TIMEOUT, verify=self.verify)
        return r
    return update_object


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

    def list_target(self, *target):
        """list organizationalUnit"""
        url = self._set_api_url_with_tuple(target)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r.json()

    def authenticate(self, userid, password,
                     domain_name=None, project_name=None):
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
        headers = {'X-Auth-Token': self.admin_token,
                   'Content-Type': 'application/json'}
        payload = {'service': {'type': service_type}}
        services = [service for service in self.list_services().get('services')
                    if service.get('type') == service_type]
        if services:
            return None
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    @_list
    def list_services(self):
        pass

    @_update
    def update_services(self):
        pass

    @_show
    def show_services(self):
        pass

    @_delete
    def delete_services(self):
        pass

    def create_endpoint(self, interface, endpoint_name,
                        endpoint_url, service_type):
        """create endpoint

        Arguments:
            interface:     [admin|public|internal]
            endpoint_name:
            endpoint_url:
            service_type:

        """
        url = self._set_api_url('endpoints')
        headers = {'X-Auth-Token': self.admin_token,
                   'Content-Type': 'application/json'}
        res = self.show_services(target_type=service_type).json()
        service_id = res.get('service').get('id')
        payload = {'endpoint': {'name': endpoint_name,
                                'url': endpoint_url,
                                'interface': interface,
                                'region': self.region,
                                'service_id': service_id}}
        endpoints = [endpoint for endpoint
                     in self.list_endpoints().get('endpoints')
                     if endpoint.get('name') == endpoint_name]
        if endpoints:
            return None
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    @_list
    def list_endpoints(self):
        pass

    @_show
    def show_endpoints(self):
        pass

    @_update
    def update_endpoints(self):
        pass

    @_delete
    def delete_endpoints(self):
        pass

    def create_role(self, role_name):
        """create role

        Arguments:
            role_name:

        """
        url = self._set_api_url('roles')
        headers = {'X-Auth-Token': self.admin_token,
                   'Content-Type': 'application/json'}
        payload = {'role': {'name': role_name}}
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    @_list
    def list_roles(self):
        pass

    @_show
    def show_roles(self):
        pass

    @_update
    def update_roles(self):
        pass

    @_delete
    def delete_roles(self):
        pass

    def grant_role_user_on_domain(self, domain_id, user_id, role_id):
        """ not implemented
            'Identity' object has no attribute 'create_grant' """
        url = self._set_api_url('domains', domain_id,
                                'users', user_id, 'roles', role_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.put(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r

    def grant_role_group_on_domain(self, domain_id, group_id, role_id):
        """ not implemented
            'Identity' object has no attribute 'create_grant' """
        url = self._set_api_url('domains', domain_id,
                                'groups', group_id, 'roles', role_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.put(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r

    @_grant_role
    def grant_role_user_on_project(self):
        pass

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

    @_list
    def list_domains(self):
        pass

    @_show
    def show_domains(self):
        pass

    # not implemented now
    @_delete
    def delete_domains(self):
        pass

    # not implemented now ?
    def update_domain(self, domain_id, domain_name,
                      enable=True, description=None,):
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
        headers = {'Content-Type': 'application/json',
                   'X-Auth-Token': self.admin_token}
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
            payload['project']['domain_id'] = retrieve_id_by_name(
                self.list_domains(),
                domain_name, 'domains')
        headers = {'Content-Type': 'application/json',
                   'X-Auth-Token': self.admin_token}
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    @_list
    def list_projects(self):
        pass

    @_show
    def show_projects(self):
        pass

    # Not Implemented
    @_delete
    def delete_projects(self):
        pass

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
            payload['group']['domain_id'] = retrieve_id_by_name(
                self.list_domains(),
                domain_name,
                'domains')
        headers = {'Content-Type': 'application/json',
                   'X-Auth-Token': self.admin_token}
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    @_list
    def list_groups(self):
        pass

    @_show
    def show_groups(self):
        pass

    @_delete
    def delete_groups(self):
        pass

    def delete_group(self, group_id=None, group_name=None):
        """delete group

        Arguments:
            group_id:
            group_name:
        """
        if group_name:
            group_id = retrieve_id_by_name(self.list_groups(),
                                           group_name, 'groups')
        url = self._set_api_url('groups', group_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.delete(url, headers=headers,
                            timeout=TIMEOUT, verify=self.verify)
        return r

    def add_user_to_group(self, user_id, group_id=None, group_name=None):
        if group_name:
            group_id = retrieve_id_by_name(self.list_groups(),
                                           group_name, 'groups')
        url = self._set_api_url('groups', group_id, 'users', user_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.put(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r

    def check_user_in_group(self, group_id, user_id):
        url = self._set_api_url('groups', group_id, 'users', user_id)
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.head(url, headers=headers,
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def list_users_in_group(self, group_id):
        url = self._set_api_url('groups', group_id, 'users')
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r.json()

    @_list
    def list_users(self):
        pass

    @_show
    def show_users(self):
        pass

    def create_credentials(self, userid, credential_type,
                           project_id, json_blob):
        """create credential, but not implemented this API.

        Arguments:
            userid:          user id
            credential_type: "ec2", etc.
            project_id:      project id
            json_blob:       JSON serialized containing 'access' and 'secret'
        """
        url = self._set_api_url('credentials')
        payload = {'credential': {'blob': json_blob,
                                  'project_id': project_id,
                                  'type': credential_type,
                                  'user_id': userid}}
        headers = {'Content-Type': 'application/json',
                   'X-Auth-Token': self.admin_token}
        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r

    @_list
    def list_credentials(self):
        pass

    @_show
    def show_credentials(self):
        pass

    @_update
    def update_credentials(self):
        pass

    @_delete
    def delete_credentials(self):
        pass

    def _get(self, url):
        """show domain

        Arguments:
            url:
        """
        headers = {'X-Auth-Token': self.admin_token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r
