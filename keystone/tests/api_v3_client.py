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
import ldap.modlist

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


def _retrieve_id(func):
    """retrieve id by (name|type|blob)

    Arguments:

        list_json:
        entry_key:
        target_key:

    """
    def retrieve_id(*args):
        data_type = func.func_name.split('retrieve_id_by_')[1]
        return [entry.get('id')
                for entry in args[0].get(args[2])
                if entry.get(data_type) == args[1]][0]
    return retrieve_id


@_retrieve_id
def retrieve_id_by_name():
    pass


@_retrieve_id
def retrieve_id_by_type():
    pass


@_retrieve_id
def retrieve_id_by_blob():
    pass


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
        self.ou_base = 'dc=auth,' + search_base
        try:
            self.conn.bind(binddn, bindpw, method)
        except ldap.SERVER_DOWN as e:
            print(e)

    def _add_entry(func):
        def add_entry(self, target_name):
            target = func.func_name.split('create_')[1] + 's'
            if target == 'domains':
                target_id = target_name
            if self.search_entry(target_name, target):
                raise ldap.ALREADY_EXIST('%s: "%s" is already existed.'
                                         % (target, target_name))
            attrs_d = {'objectClass': ['groupOfNames'],
                       'description': [target_name],
                       'businessCategory': [target_id],
                       'ou': [target_name],
                       'enabled': ['TRUE'],
                       'member': ['cn=dumb,dc=noexistent'],
                       'cn': [target_id]}
            attrs_l = ldap.modlist.addModlist(attrs_d)
            entry_dn = 'cn=%s,ou=%s,%s' % (target_id, target, self.ou_base)
            return self.conn.add_s(entry_dn, attrs_l)
        return add_entry

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

    @_add_entry
    def create_domain(self, target_id):
        pass


def _create(func):
    """create target"""
    def create_object(self, **kwargs):
        """

        Arguments:

            target_id:
            target_name:
            target_type:
            target_blob:
            token:

        """
        target = func.func_name.split('create_')[1]
        if kwargs.get('token'):
            token = kwargs.get('token')

        payload = {target: {}}
        if kwargs.get('target_type'):
            payload[target]['type'] = kwargs.get('target_type')
        if kwargs.get('target_name'):
            payload[target]['name'] = kwargs.get('target_name')
        if kwargs.get('target_blob'):
            payload[target]['blob'] = kwargs.get('target_blob')

        if target == 'endpoint':
            res = self.show_services(token=token,
                                     target_type=kwargs.get('service_type'))
            payload[target]['service_id'] = res.json().get('service').get('id')
            payload[target]['url'] = kwargs.get('url')
            payload[target]['interface'] = kwargs.get('interface')
            payload[target]['region'] = self.region
        elif target == 'domain' or target == 'project' or target == 'group':
            payload[target]['enabled'] = True
            payload[target]['description'] = kwargs.get('target_name')

            if kwargs.get('domain_name'):
                payload[target]['domain_id'] = retrieve_id_by_name(
                    self.list_domains(token=token),
                    kwargs.get('domain_name'),
                    'domains')
        elif target == 'credential':
            payload[target]['project_id'] = kwargs.get('project_id')
            payload[target]['user_id'] = kwargs.get('user_id')

        if target == 'policy':
            url = self._set_api_url('policies')
        else:
            url = self._set_api_url(target + 's')

        headers = {'X-Auth-Token': token, 'Content-Type': 'application/json'}

        r = requests.post(url, headers=headers, data=json.dumps(payload),
                          timeout=TIMEOUT, verify=self.verify)
        return r
    return create_object


def _list(func):
    """list organizationalUnit"""
    def list_objects(self, *args, **kwargs):
        target = (func.func_name.split('list_')[1],)
        if args:
            target += args
        if kwargs.get('token'):
            token = kwargs.get('token')
        url = self._set_api_url_with_tuple(target)
        headers = {'X-Auth-Token': token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r.json()
    return list_objects


def _show(func):
    """show target"""
    def show_object(self, **kwargs):
        """

        Arguments:

            target_id:
            target_name:
            target_type:
            target_blob:
            token:

        """
        target = func.func_name.split('show_')[1]

        if kwargs.get('token'):
            token = kwargs.get('token')

        if kwargs.get('target_type'):
            target_id = retrieve_id_by_type(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_type'),
                                            target)
        elif kwargs.get('target_name'):
            target_id = retrieve_id_by_name(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_name'),
                                            target)
        elif kwargs.get('target_blob'):
            target_id = retrieve_id_by_blob(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_blob'),
                                            target)
        elif kwargs.get('target_id'):
            target_id = kwargs.get('target_id')
        url = self._set_api_url(target, target_id)

        headers = {'X-Auth-Token': token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r
    return show_object


def _delete(func):
    """delete target"""
    def delete_object(self, **kwargs):
        """

        Arguments:

            target:
            target_id:
            target_name:
            target_blob:
            token:

        """
        target = func.func_name.split('delete_')[1]
        if target == 'policy':
            target = 'policie'
        target += 's'

        if kwargs.get('token'):
            token = kwargs.get('token')

        if kwargs.get('target_type'):
            target_id = retrieve_id_by_type(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_type'),
                                            target)
        elif kwargs.get('target_name'):
            target_id = retrieve_id_by_name(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_name'),
                                            target)
        elif kwargs.get('target_blob'):
            target_id = retrieve_id_by_blob(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_blob'),
                                            target)
        elif kwargs.get('target_id'):
            target_id = kwargs.get('target_id')

        url = self._set_api_url(target, target_id)

        headers = {'X-Auth-Token': token}
        r = requests.delete(url, headers=headers,
                            timeout=TIMEOUT, verify=self.verify)
        return r
    return delete_object


def _update(func):
    """ update target """
    def update_object(self, **kwargs):
        """

        Arguments:
            target_id:
            target_name:
            token:

        """
        target = func.func_name.split('update_')[1]
        if target == 'policy':
            target = 'policie'
        target += 's'

        if kwargs.get('token'):
            token = kwargs.get('token')

        if kwargs.get('target_type'):
            target_id = retrieve_id_by_type(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_type'),
                                            target)
        elif kwargs.get('target_name'):
            target_id = retrieve_id_by_name(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_name'),
                                            target)
        elif kwargs.get('target_id'):
            target_id = kwargs.get('target_id')

        url = self._set_api_url(target, target_id)

        headers = {'X-Auth-Token': token,
                   'Content-Type': 'application/json'}

        if kwargs.get('payload'):
            payload = kwargs.get('payload')
        else:
            payload = None
        r = requests.patch(url, headers=headers, data=json.dumps(payload),
                           timeout=TIMEOUT, verify=self.verify)
        return r
    return update_object


def _grant_role(func):
    """grant role to <user|group> on <domain|project>"""
    def grant_role(self, **kwargs):
        """

        Arguments:
            target_id:
            target_name:
            ou_id:
            ou_name:
            token:

        """
        target = func.func_name.split('grant_role_')[1].split('_')[0] + 's'

        if kwargs.get('token'):
            token = kwargs.get('token')

        if kwargs.get('target_name'):
            target_id = retrieve_id_by_name(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_name'),
                                            target)
        elif kwargs.get('target_id'):
            target_id = kwargs.get('target_id')

        ou_target = func.func_name.split('_on_')[1] + 's'
        if kwargs.get('ou_name'):
            ou_id = retrieve_id_by_name(self.list_target(ou_target,
                                                         token=token),
                                        kwargs.get('ou_name'),
                                        ou_target)
        elif kwargs.get('ou_id'):
            ou_id = kwargs.get('ou_id')

        if kwargs.get('role_name'):
            role_id = retrieve_id_by_name(self.list_target('roles',
                                                           token=token),
                                          kwargs.get('role_name'),
                                          'roles')
        elif kwargs.get('role_id'):
            role_id = kwargs.get('role_id')

        url = self._set_api_url(ou_target, ou_id,
                                target, target_id,
                                'roles', role_id)

        headers = {'X-Auth-Token': token}
        r = requests.put(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r
    return grant_role


def _list_grants(func):
    """list roles to <user|group> on <domain|project>"""
    def list_grants(self, **kwargs):
        """

        Arguments:

            target_id:
            target_name:
            ou_id:
            ou_name:
            token:

        """
        target = func.func_name.split('list_roles_')[1].split('_')[0] + 's'

        if kwargs.get('token'):
            token = kwargs.get('token')

        if kwargs.get('target_name'):
            target_id = retrieve_id_by_name(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_name'),
                                            target)
        elif kwargs.get('target_id'):
            target_id = kwargs.get('target_id')

        ou_target = func.func_name.split('_on_')[1] + 's'
        if kwargs.get('ou_name'):
            ou_id = retrieve_id_by_name(self.list_target(ou_target,
                                                         token=token),
                                        kwargs.get('ou_name'),
                                        ou_target)
        elif kwargs.get('ou_id'):
            ou_id = kwargs.get('ou_id')

        url = self._set_api_url(ou_target, ou_id,
                                target, target_id, 'roles')

        headers = {'X-Auth-Token': token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r
    return list_grants


def _check_grant(func):
    """check <user|group> has role on <project|domain>"""
    def check_grant(self, **kwargs):
        """

        Arguments:

            target_id:
            target_name:
            ou_id:
            ou_name:
            role_id:
            role_name:
            token:

        """
        target = func.func_name.split('check_')[1].split('_')[0] + 's'

        if kwargs.get('token'):
            token = kwargs.get('token')

        if kwargs.get('target_name'):
            target_id = retrieve_id_by_name(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_name'),
                                            target)
        elif kwargs.get('target_id'):
            target_id = kwargs.get('target_id')

        ou_target = func.func_name.split('_on_')[1] + 's'
        if kwargs.get('ou_name'):
            ou_id = retrieve_id_by_name(self.list_target(ou_target,
                                                         token=token),
                                        kwargs.get('ou_name'),
                                        ou_target)
        elif kwargs.get('ou_id'):
            ou_id = kwargs.get('ou_id')

        if kwargs.get('role_name'):
            role_id = retrieve_id_by_name(self.list_target('roles',
                                                           token=token),
                                          kwargs.get('role_name'),
                                          'roles')
        elif kwargs.get('role_id'):
            role_id = kwargs.get('role_id')

        url = self._set_api_url(ou_target, ou_id,
                                target, target_id,
                                'roles', role_id)

        headers = {'X-Auth-Token': token}
        r = requests.head(url, headers=headers,
                          timeout=TIMEOUT, verify=self.verify)
        return r
    return check_grant


def _revoke_grant(func):
    """revoke role from <user|group> on <project|domain>"""
    def revoke_grant(self, **kwargs):
        """

        Arguments:
            target_id:
            target_name:
            ou_id:
            ou_name:
            role_id:
            role_name:
            token:
        """
        target = (func.func_name.split('revoke_role_from_')[1].split('_')[0]
                  + 's')

        if kwargs.get('token'):
            token = kwargs.get('token')

        if kwargs.get('target_name'):
            target_id = retrieve_id_by_name(self.list_target(target,
                                                             token=token),
                                            kwargs.get('target_name'),
                                            target)
        elif kwargs.get('target_id'):
            target_id = kwargs.get('target_id')

        ou_target = func.func_name.split('_on_')[1] + 's'
        if kwargs.get('ou_name'):
            ou_id = retrieve_id_by_name(self.list_target(ou_target,
                                                         token=token),
                                        kwargs.get('ou_name'),
                                        ou_target)
        elif kwargs.get('ou_id'):
            ou_id = kwargs.get('ou_id')

        if kwargs.get('role_name'):
            role_id = retrieve_id_by_name(self.list_target('roles',
                                                           token=token),
                                          kwargs.get('role_name'),
                                          'roles')
        elif kwargs.get('role_id'):
            role_id = kwargs.get('role_id')

        url = self._set_api_url(ou_target, ou_id,
                                target, target_id,
                                'roles', role_id)

        headers = {'X-Auth-Token': token}
        r = requests.delete(url, headers=headers,
                            timeout=TIMEOUT, verify=self.verify)
        return r
    return revoke_grant


class ApiV3Client(object):

    def __init__(self, base_url, region, verify=True):
        """initialize variable

        Arguments:
            base_url:
            admin_token:
            verify:
        """
        self.base_url = base_url
        self.verify = verify
        self.region = region

    def _set_api_url(self, *kwargs):
        """return api url

        Arguments:
            *kwargs:
        """
        url = self.base_url
        for i in kwargs:
            url = os.path.join(url, i)
        return url

    def _set_api_url_with_tuple(self, kwargs):
        """return api url

        Arguments:
            *kwargs:
        """
        url = self.base_url
        for i in kwargs:
            url = os.path.join(url, i)
        return url

    def list_target(self, *target, **kwargs):
        """list organizationalUnit"""
        url = self._set_api_url_with_tuple(target)
        headers = {'X-Auth-Token': kwargs.get('token')}
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

    def validate_token(self, subject_token, auth_token):
        url = self._set_api_url('auth/tokens')
        headers = {'X-Auth-Token': auth_token,
                   'X-Subject-Token': subject_token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r

    def check_token(self, subject_token, auth_token):
        url = self._set_api_url('auth/tokens')
        headers = {'X-Auth-Token': auth_token,
                   'X-Subject-Token': subject_token}
        r = requests.head(url, headers=headers,
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def revoke_token(self, subject_token, auth_token):
        url = self._set_api_url('auth/tokens')
        headers = {'X-Auth-Token': auth_token,
                   'X-Subject-Token': subject_token}
        r = requests.delete(url, headers=headers,
                            timeout=TIMEOUT, verify=self.verify)
        return r

    @_create
    def create_service(self):
        pass

    @_list
    def list_services(self):
        pass

    @_update
    def update_service(self):
        pass

    @_show
    def show_services(self):
        pass

    @_delete
    def delete_service(self):
        pass

    @_create
    def create_endpoint(self):
        pass

    @_list
    def list_endpoints(self):
        pass

    @_show
    def show_endpoints(self):
        pass

    @_update
    def update_endpoint(self):
        pass

    @_delete
    def delete_endpoint(self):
        pass

    @_create
    def create_role(self):
        pass

    @_list
    def list_roles(self):
        pass

    @_show
    def show_roles(self):
        pass

    @_update
    def update_role(self):
        pass

    @_delete
    def delete_role(self):
        pass

    @_grant_role
    def grant_role_user_on_domain(self):
        """ Not Implmented"""
        pass

    @_grant_role
    def grant_role_group_on_domain(self):
        """ Not Implmented"""
        pass

    @_grant_role
    def grant_role_user_on_project(self):
        """ Not Implmented"""
        pass

    @_grant_role
    def grant_role_group_on_project(self):
        """ Not Implmented"""
        pass

    @_list_grants
    def list_roles_user_on_domain(self):
        """ Not Implmented"""
        pass

    @_list_grants
    def list_roles_group_on_domain(self):
        """ Not Implmented"""
        pass

    @_list_grants
    def list_roles_user_on_project(self):
        """ Not Implmented"""
        pass

    @_list_grants
    def list_roles_group_on_project(self):
        """ Not Implmented"""
        pass

    @_check_grant
    def check_user_has_role_on_domain(self):
        """ Not Implmented"""
        pass

    @_check_grant
    def check_group_has_role_on_domain(self):
        """ Not Implmented"""
        pass

    @_check_grant
    def check_user_has_role_on_project(self):
        """ Not Implmented"""
        pass

    @_check_grant
    def check_group_has_role_on_project(self):
        """ Not Implmented"""
        pass

    @_revoke_grant
    def revoke_role_from_user_on_domain(self):
        """ Not Implmented"""
        pass

    @_revoke_grant
    def revoke_role_from_group_on_domain(self):
        """ Not Implmented"""
        pass

    @_revoke_grant
    def revoke_role_from_user_on_project(self):
        """ Not Implmented"""
        pass

    @_revoke_grant
    def revoke_role_from_group_on_project(self):
        """ Not Implmented"""
        pass

    @_create
    def create_domain(self):
        pass

    @_list
    def list_domains(self):
        pass

    @_show
    def show_domains(self):
        pass

    # not implemented now
    @_delete
    def delete_domain(self):
        pass

    # not implemented now ?
    def update_domain(self, token, domain_id, domain_name,
                      enable=True, description=None):
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
                   'X-Auth-Token': token}
        r = requests.patch(url, headers=headers, data=json.dumps(payload),
                           timeout=TIMEOUT, verify=self.verify)
        return r

    @_create
    def create_project(self):
        pass

    @_list
    def list_projects(self):
        pass

    @_show
    def show_projects(self):
        pass

    # Not Implemented
    @_delete
    def delete_project(self):
        pass

    @_create
    def create_group(self):
        pass

    @_list
    def list_groups(self):
        pass

    @_show
    def show_groups(self):
        pass

    @_delete
    def delete_group(self):
        pass

    def add_user_to_group(self, user_id, **kwargs):
        if kwargs.get('token'):
            token = kwargs.get('token')
        if kwargs.get('group_id'):
            group_id = kwargs.get('group_id')
        elif kwargs.get('group_name'):
            group_id = retrieve_id_by_name(self.list_groups(token=token),
                                           kwargs.get('group_name'),
                                           'groups')
        url = self._set_api_url('groups', group_id, 'users', user_id)
        headers = {'X-Auth-Token': token}
        r = requests.put(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r

    def check_user_in_group(self, token, group_id, user_id):
        url = self._set_api_url('groups', group_id, 'users', user_id)
        headers = {'X-Auth-Token': token}
        r = requests.head(url, headers=headers,
                          timeout=TIMEOUT, verify=self.verify)
        return r

    def list_users_in_group(self, token, group_id):
        url = self._set_api_url('groups', group_id, 'users')
        headers = {'X-Auth-Token': token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r.json()

    @_list
    def list_users(self):
        pass

    @_show
    def show_users(self):
        pass

    @_create
    def create_credential(self):
        pass

    @_list
    def list_credentials(self):
        pass

    @_show
    def show_credentials(self):
        pass

    @_update
    def update_credential(self):
        pass

    @_delete
    def delete_credential(self):
        pass

    def _get(self, token, url):
        """show domain

        Arguments:
            url:
        """
        headers = {'X-Auth-Token': token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r

    @_create
    def create_policy(self):
        pass

    @_list
    def list_policies(self):
        pass

    @_show
    def show_policies(self):
        pass

    @_delete
    def delete_policy(self):
        pass

    @_update
    def update_policy(self):
        pass

    def get_role_assginments(self, **kwargs):
        if kwargs.get('token'):
            token = kwargs.get('token')

        url = self._set_api_url_with_tuple(('role_assignments',))
        headers = {'X-Auth-Token': token}
        r = requests.get(url, headers=headers,
                         timeout=TIMEOUT, verify=self.verify)
        return r.json()
