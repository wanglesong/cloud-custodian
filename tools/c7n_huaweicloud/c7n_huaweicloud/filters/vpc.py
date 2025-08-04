# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from c7n.exceptions import PolicyValidationError
from c7n.filters.core import Filter, ValueFilter
from c7n.filters.related import RelatedResourceFilter
from c7n.utils import type_schema, local_session

log = logging.getLogger('custodian.huaweicloud.filters.vpc')


class MatchResourceValidator:
    """Verify the filter parameters for matching resources.

    Used to verify filter configuration with match-resource parameter.
    """

    def validate(self):
        if self.data.get('match-resource'):
            self.required_keys = set('key', )
        return super(MatchResourceValidator, self).validate()


class SecurityGroupFilter(MatchResourceValidator, RelatedResourceFilter):
    """Filter resources based on associated security groups attributes.

    This filter allows filtering resources based on associated security group attributes,
    such as security group name, ID, or tags.

    :example:

    .. code-block:: yaml

        policies:
          - name: instances-in-sg-with-public-access
            resource: huaweicloud.ecs
            filters:
              - type: security-group
                key: name
                value: allow-public-access
    """
    schema = type_schema(
        'security-group', rinherit=ValueFilter.schema,
        **{'match-resource': {'type': 'boolean'},
           'operator': {'enum': ['and', 'or']}})
    schema_alias = True

    # The associated resource type is huaweicloud.vpc-security-group
    RelatedResource = "c7n_huaweicloud.resources.vpc.SecurityGroup"
    AnnotationKey = "matched-security-groups"


class SubnetFilter(MatchResourceValidator, RelatedResourceFilter):
    """Filter resources based on associated subnet attributes.

    This filter is used for network attached resources and can be filtered
    based on the attributes of subnets.
    For example, searching for resources connected to a specific subnet,
    or searching for resources connected to a public subnet.

    :example:

    .. code-block:: yaml

        policies:
          - name: instances-in-production-subnet
            resource: huaweicloud.ecs
            filters:
              - type: subnet
                key: tag:Environment
                value: Production

        policies:
          - name: instances-in-public-subnet
            resource: huaweicloud.ecs
            filters:
              - type: subnet
                igw: True
    """

    schema = type_schema(
        'subnet', rinherit=ValueFilter.schema,
        **{'match-resource': {'type': 'boolean'},
           'operator': {'enum': ['and', 'or']},
           'igw': {'enum': [True, False]},
           })

    schema_alias = True
    RelatedResource = "c7n_huaweicloud.resources.vpc.Subnet"
    AnnotationKey = "matched-subnets"

    def get_permissions(self):
        perms = super().get_permissions()
        if self.data.get('igw') in (True, False):
            perms += self.manager.get_resource_manager(
                'huaweicloud.vpc-route-table').get_permissions()
        return perms

    def validate(self):
        super().validate()
        self.check_igw = self.data.get('igw')

    def match(self, related):
        if self.check_igw in [True, False]:
            if not self.match_igw(related):
                return False
        return super().match(related)

    def process(self, resources, event=None):
        related = self.get_related(resources)
        if self.check_igw in [True, False]:
            self.route_tables = self.get_route_tables()
        return [r for r in resources if self.process_resource(r, related)]

    def get_route_tables(self):
        rmanager = self.manager.get_resource_manager('huaweicloud.vpc-route-table')
        route_tables = {}
        for r in rmanager.resources():
            for a in r.get('routes', []):
                if a.get('destination') == '0.0.0.0/0' and a.get('type') == 'peering':
                    vpc_id = r.get('vpc_id')
                    route_tables.setdefault(vpc_id, []).append(r)
        return route_tables

    def match_igw(self, subnet):
        vpc_id = subnet.get('vpc_id')
        if vpc_id not in self.route_tables:
            self.log.debug('route table for vpc %s not found', vpc_id)
            return False

        if self.check_igw:
            # If a public subnet is required, check whether the VPC has a route to the Internet
            return bool(self.route_tables.get(vpc_id))
        else:
            # If a private subnet is required, check whether the VPC has no route to the Internet
            return not bool(self.route_tables.get(vpc_id))


class VpcFilter(MatchResourceValidator, RelatedResourceFilter):
    """Filter resources based on associated vpc attributes.

    This filter allows filtering resources based on VPC attributes.

    :example:

    .. code-block:: yaml

        policies:
          - name: instances-in-production-vpc
            resource: huaweicloud.ecs
            filters:
              - type: vpc
                key: tag:Environment
                value: Production
    """
    schema = type_schema(
        'vpc', rinherit=ValueFilter.schema,
        **{'match-resource': {'type': 'boolean'},
           'operator': {'enum': ['and', 'or']}})

    schema_alias = True
    RelatedResource = "c7n_huaweicloud.resources.vpc.Vpc"
    AnnotationKey = "matched-vpcs"


class DefaultVpcBase(Filter):
    """Filter resources in the default VPC

    Used to filter resources in the default VPC.

    :example:

    .. code-block:: yaml

        policies:
          - name: instances-in-default-vpc
            resource: huaweicloud.ecs
            filters:
              - type: default-vpc
    """
    vpcs = None
    default_vpc = None
    permissions = ()

    def match(self, vpc_id):
        if self.default_vpc is None:
            self.log.debug("Query default VPC %s" % vpc_id)
            client = local_session(self.manager.session_factory).client('vpc')
            vpcs = []
            for vpc in client.list_vpcs().vpcs:
                if getattr(vpc, 'is_default', False):
                    vpcs.append(vpc.id)
            if vpcs:
                self.default_vpc = vpcs[0]
        return vpc_id == self.default_vpc and True or False


class NetworkLocation(Filter):
    """Check the intersection of security groups, subnets,
    and resource attributes of network attached resources

    This filter is designed for specific cases, and for most use cases,
    using the 'subnet' and 'security group' filters is sufficient.
    For example, to verify whether an ECS instance only uses subnets
    and security groups with a given tag value,
    and that the tag does not exist on the resource.

    :example:

    .. code-block:: yaml

        policies:
          - name: ecs-mismatched-sg-remove
            resource: huaweicloud.ecs
            filters:
              - type: network-location
                compare: ["resource","security-group"]
                key: "tag:TEAM_NAME"
                ignore:
                  - "tag:TEAM_NAME": Enterprise
            actions:
              - type: modify-security-groups
                remove: network-location
                isolation-group: sg-xxxxxxxx
    """

    schema = type_schema(
        'network-location',
        **{'missing-ok': {
            'type': 'boolean',
            'default': False,
            'description': (
                "How to deal with missing keys on elements, "
                "which by default can cause resources to be treated as unequal")},
            'match': {'type': 'string', 'enum': ['equal', 'not-equal', 'in'],
                      'default': 'non-equal'},
            'compare': {
                'type': 'array',
                'description': (
                    'Elements to consider when comparing network locations.'),
                'default': ['resource', 'subnet', 'security-group'],
                'items': {
                    'enum': ['resource', 'subnet', 'security-group']}},
            'key': {
                'type': 'string',
                'description': 'The attribute expression that should be matched.'},
            'max-cardinality': {
                'type': 'integer', 'default': 1,
                'title': ''},
            'ignore': {'type': 'array', 'items': {'type': 'object'}},
            'required': ['key'],
            'value': {'type': 'array', 'items': {'type': 'string'}}
        })
    schema_alias = True
    permissions = ()

    def validate(self):
        rfilters = self.manager.filter_registry.keys()
        if 'subnet' not in rfilters:
            raise PolicyValidationError(
                "network-location requires subnet filters to be available on %s" % (
                    self.manager.data))

        if 'security-group' not in rfilters:
            raise PolicyValidationError(
                "network-location requires security-group filters to be available on %s" % (
                    self.manager.data))
        return self

    def process(self, resources, event=None):
        self.sg = self.manager.filter_registry.get('security-group')({}, self.manager)
        related_sg = self.sg.get_related(resources)

        self.subnet = self.manager.filter_registry.get('subnet')({}, self.manager)
        related_subnet = self.subnet.get_related(resources)

        self.sg_model = self.manager.get_resource_manager('security-group').get_model()
        self.subnet_model = self.manager.get_resource_manager('subnet').get_model()
        self.vf = self.manager.filter_registry.get('value')({}, self.manager)

        # filter options
        key = self.data.get('key')
        self.compare = self.data.get('compare', ['subnet', 'security-group', 'resource'])
        self.max_cardinality = self.data.get('max-cardinality', 1)
        self.match = self.data.get('match', 'not-equal')
        self.missing_ok = self.data.get('missing-ok', False)

        results = []
        for r in resources:
            resource_sgs = self.filter_ignored(
                [related_sg[sid] for sid in self.sg.get_related_ids([r]) if sid in related_sg])
            resource_subnets = self.filter_ignored(
                [related_subnet[sid] for sid in self.subnet.get_related_ids([r])
                 if sid in related_subnet])
            found = self.process_resource(r, resource_sgs, resource_subnets, key)
            if found:
                results.append(found)

        return results

    def filter_ignored(self, resources):
        ignores = self.data.get('ignore', ())
        results = []

        for r in resources:
            found = False
            for i in ignores:
                for k, v in i.items():
                    if self.vf.get_resource_value(k, r) == v:
                        found = True
                if found is True:
                    break
            if found is True:
                continue
            results.append(r)
        return results

    def process_resource(self, r, resource_sgs, resource_subnets, key):
        evaluation = []
        sg_space = set()
        subnet_space = set()

        if self.match == 'in':
            return self.process_match_in(r, resource_sgs, resource_subnets, key)

        if 'subnet' in self.compare:
            subnet_values = {
                rsub[self.subnet_model.id]: self.subnet.get_resource_value(key, rsub)
                for rsub in resource_subnets}

            if not self.missing_ok and None in subnet_values.values():
                evaluation.append({
                    'reason': 'SubnetLocationAbsent',
                    'subnets': subnet_values})
            subnet_space = set(filter(None, subnet_values.values()))

            if len(subnet_space) > self.max_cardinality:
                evaluation.append({
                    'reason': 'SubnetLocationCardinality',
                    'subnets': subnet_values})

        if 'security-group' in self.compare:
            sg_values = {
                rsg[self.sg_model.id]: self.sg.get_resource_value(key, rsg)
                for rsg in resource_sgs}
            if not self.missing_ok and None in sg_values.values():
                evaluation.append({
                    'reason': 'SecurityGroupLocationAbsent',
                    'security-groups': sg_values})

            sg_space = set(filter(None, sg_values.values()))

            if len(sg_space) > self.max_cardinality:
                evaluation.append({
                    'reason': 'SecurityGroupLocationCardinality',
                    'security-groups': sg_values})

        if ('subnet' in self.compare and
                'security-group' in self.compare and
                sg_space != subnet_space):
            evaluation.append({
                'reason': 'LocationMismatch',
                'subnets': subnet_values,
                'security-groups': sg_values})

        if 'resource' in self.compare:
            r_value = self.vf.get_resource_value(key, r)
            if not self.missing_ok and r_value is None:
                evaluation.append({
                    'reason': 'ResourceLocationAbsent',
                    'resource': r_value})
            elif 'security-group' in self.compare and resource_sgs and r_value not in sg_space:
                evaluation.append({
                    'reason': 'ResourceLocationMismatch',
                    'resource': r_value,
                    'security-groups': sg_values})
            elif 'subnet' in self.compare and resource_subnets and r_value not in subnet_space:
                evaluation.append({
                    'reason': 'ResourceLocationMismatch',
                    'resource': r_value,
                    'subnet': subnet_values})
            if 'security-group' in self.compare and resource_sgs:
                mismatched_sgs = {sg_id: sg_value
                                  for sg_id, sg_value in sg_values.items()
                                  if sg_value != r_value}
                if mismatched_sgs:
                    evaluation.append({
                        'reason': 'SecurityGroupMismatch',
                        'resource': r_value,
                        'security-groups': mismatched_sgs})

        if evaluation and self.match == 'not-equal':
            r['c7n:NetworkLocation'] = evaluation
            return r
        elif not evaluation and self.match == 'equal':
            return r

    def process_match_in(self, r, resource_sgs, resource_subnets, key):
        network_location_vals = set(self.data.get('value', []))

        if 'subnet' in self.compare:
            subnet_values = {
                rsub[self.subnet_model.id]: self.subnet.get_resource_value(key, rsub)
                for rsub in resource_subnets}
            if not self.missing_ok and None in subnet_values.values():
                return

            subnet_space = set(filter(None, subnet_values.values()))
            if not subnet_space.issubset(network_location_vals):
                return

        if 'security-group' in self.compare:
            sg_values = {
                rsg[self.sg_model.id]: self.sg.get_resource_value(key, rsg)
                for rsg in resource_sgs}
            if not self.missing_ok and None in sg_values.values():
                return

            sg_space = set(filter(None, sg_values.values()))

            if not sg_space.issubset(network_location_vals):
                return

        if 'resource' in self.compare:
            r_value = self.vf.get_resource_value(key, r)
            if not self.missing_ok and r_value is None:
                return

            if r_value not in network_location_vals:
                return

        return r
