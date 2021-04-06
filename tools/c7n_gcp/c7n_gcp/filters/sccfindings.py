# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Security Command Center Findings suppport for GCP resources
"""
from c7n.filters.core import ValueFilter
from c7n.utils import local_session, type_schema
from c7n_gcp.provider import resources as gcp_resources


class SecurityComandCenterFindingsFilter(ValueFilter):
    """Filters resources based on their Security Command Center (SCC) findings.

    .. code-block:: yaml

      - name: bucket-contains-finding
        resource: gcp.bucket
        filters:
        - scc-finding

      - name: bucket-contains-high-finding
        resource: gcp.bucket
        filters:
        - type: scc-finding
          key: findings[].category
          op: contains
          value: BUCKET_LOGGING_DISABLED 
    """

    schema = type_schema('scc-findings', rinherit=ValueFilter.schema, org={'type':'integer'}, required=['org'])
    required_keys = {}

    def process(self, resources, event=None):
        self.findings_by_resource = {}

        session = local_session(self.manager.session_factory)
        client = session.client("securitycenter", "v1", "organizations.sources.findings")
        project = session.get_default_project()

        query_params = {
            'filter': self.get_resource_filter(resources),
            'pageSize': 1000
        }
        findings_list = client.execute_query('list', {'parent': 'organizations/{}/sources/-'.format(self.data['org']), **query_params})

        if not findings_list.get('listFindingsResults'):
            findings_list = {'listFindingsResults':[]}

        self.split_by_resource(findings_list['listFindingsResults'])

        matched = [r for r in resources if self.process_resource(r)]

        return matched

    def get_resource_filter(self, resources):
        resource_filter = []
        for r in resources:
            resource_filter.append('resourceName:"{}"'.format(r[self.manager.resource_type.name]))
            resource_filter.append(' OR ')
        resource_filter.pop()

        return ''.join(resource_filter)

    def split_by_resource(self, finding_list):
        for f in finding_list:
            resource_name = f["finding"]["resourceName"].split('/')[-1]
            resource_findings = self.findings_by_resource.get(resource_name,[])
            resource_findings.append(f)
            self.findings_by_resource[resource_name] = resource_findings

    def process_resource(self, resource):
        resource_name = resource[self.manager.resource_type.name]
        resource_findings = self.findings_by_resource.get(resource_name,[])
        resource.setdefault('c7n.findings', []).extend(resource_findings)

        if not self.data.get('key'):
            return len(resource_findings) > 0

        return self.match(resource_findings)

    @classmethod
    def register_resources(klass, registry, resource_class):
        resource_class.filter_registry.register('scc-findings', klass)


gcp_resources.subscribe(SecurityComandCenterFindingsFilter.register_resources)
