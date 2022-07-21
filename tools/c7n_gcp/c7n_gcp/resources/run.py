# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo, GcpLocation
from c7n.utils import local_session


@resources.register('run-service')
class RunService(QueryResourceManager):
    """
    https://cloud.google.com/run/docs/reference/rest/v2/projects.locations.services
    """
    class resource_type(TypeInfo):
        service = 'run'
        version = 'v2'
        component = 'projects.locations.services'
        enum_spec = ('list', 'services[]', None)
        scope = None
        name = id = 'name'
        default_report_fields = [
            "name", "description", "creator", "uri"]
        labels = True
        labels_op = 'patch'
        metric_key = "resource.labels.service_name"
        
        # @staticmethod
        # def get(client, resource_info):
        #     name = 'projects/{}/locations/{}/services/{}' \
        #         .format(resource_info['project_id'],
        #                 resource_info['location'],
        #                 resource_info['id'])
        #     return client.execute_command('get', {'name': name})

    def _fetch_resources(self, query):
        super_fetch_resources = QueryResourceManager._fetch_resources
        session = local_session(self.session_factory)
        project = session.get_default_project()
        locations = (query['parent'] if query and 'parent' in query
                    else GcpLocation.get_service_locations('run'))
        location = ['us-central1']
        project_locations = ['projects/{}/locations/{}'.format(project, location)
                            for location in locations]
        run_services = []
        for location in project_locations:
            run_services.extend(super_fetch_resources(self, {'parent': location}))
        return run_services
