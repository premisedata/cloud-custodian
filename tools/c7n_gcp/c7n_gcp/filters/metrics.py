# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
"""
Monitoring Metrics suppport for resources
"""
from datetime import datetime, timedelta
import pytz

import jmespath

from c7n.filters.core import Filter, OPERATORS
from c7n.utils import local_session, type_schema

from c7n_gcp.provider import resources as gcp_resources

REDUCERS = [
    'REDUCE_NONE',
    'REDUCE_MEAN',
    'REDUCE_MIN',
    'REDUCE_MAX',
    'REDUCE_MEAN',
    'REDUCE_SUM',
    'REDUCE_STDDEV',
    'REDUCE_COUNT',
    'REDUCE_COUNT_TRUE',
    'REDUCE_COUNT_FALSE',
    'REDUCE_FRACTION_TRUE',
    'REDUCE_PERCENTILE_99',
    'REDUCE_PERCENTILE_95',
    'REDUCE_PERCENTILE_50',
    'REDUCE_PERCENTILE_05']

ALIGNERS = [
    'ALIGN_NONE',
    'ALIGN_DELTA',
    'ALIGN_RATE',
    'ALIGN_INTERPOLATE',
    'ALIGN_MIN',
    'ALIGN_MAX',
    'ALIGN_MEAN',
    'ALIGN_COUNT',
    'ALIGN_SUM',
    'REDUCE_COUNT_FALSE',
    'ALIGN_STDDEV',
    'ALIGN_COUNT_TRUE',
    'ALIGN_COUNT_FALSE',
    'ALIGN_FRACTION_TRUE',
    'ALIGN_PERCENTILE_99',
    'ALIGN_PERCENTILE_95',
    'ALIGN_PERCENTILE_50',
    'ALIGN_PERCENTILE_05',
    'ALIGN_PERCENT_CHANG']


class GCPMetricsFilter(Filter):
    """Supports metrics filters on resources.

    All resources that have cloud watch metrics are supported.

    Docs on cloud watch metrics

    - Google Supported Metrics
      https://cloud.google.com/monitoring/api/metrics_gcp

    - Custom Metrics
      https://cloud.google.com/monitoring/api/v3/metric-model#intro-custom-metrics

    .. code-block:: yaml

      - name: firewall-hit-count
        resource: gcp.firewall
        filters:
        - type: metrics
          name: firewallinsights.googleapis.com/subnet/firewall_hit_count
          metric_key: metric.labels.firewall_name
          resource_key: name
          aligner: ALIGN_COUNT
          days: 14
          value: 1
          op: greater-than
    """

    schema = type_schema(
        'metrics',
        **{'name': {'type': 'string'},
          'resource-key': {'type': 'string'},
          'metric-key': {'type': 'string'},
          'group-by-fields': {'type': 'array', 'items': {'type', 'string'}},
          'days': {'type': 'number'},
          'op': {'type': 'string', 'enum': list(OPERATORS.keys())},
          'reducer': {'type': 'string', 'enum': REDUCERS},
          'aligner': {'type': 'string', 'enum': ALIGNERS},
          'value': {'type': 'number'},
          'period': {'type': 'number'},
          'missing-value': {'type': 'number'},
          'required': ('value', 'name', 'op')})
    schema_alias = True
    permissions = ("monitoring.timeSeries.list",)

    def process(self, resources, event=None):
        days = self.data.get('days', 14)
        duration = timedelta(days)

        self.metric = self.data['name']
        self.resource_key = self.data['resource-key']
        self.metric_key = self.data['metric-key']
        self.aligner = self.data.get('aligner', 'ALIGN_NONE')
        self.reducer = self.data.get('reducer', 'REDUCE_NONE')
        self.group_by_fields = self.data.get('group-by-fields', [])
        self.missing_value = self.data.get('missing-value', 0)
        self.end = datetime.now(pytz.timezone('UTC'))
        self.start = self.end - duration
        self.period = str((self.end - self.start).total_seconds()) + 's'
        self.resource_metric_dict = {}
        self.op = OPERATORS[self.data.get('op', 'less-than')]
        self.value = self.data['value']

        session = local_session(self.manager.session_factory)
        client = session.client("monitoring", "v3", "projects.timeSeries")
        project = session.get_default_project()

        query_params = {
            'filter': self.get_query_filter(resources),
            'interval_startTime': self.start.isoformat(),
            'interval_endTime': self.end.isoformat(),
            'aggregation_alignmentPeriod': self.period,
            "aggregation_perSeriesAligner": self.aligner,
            "aggregation_crossSeriesReducer": self.reducer,
            "aggregation_groupByFields": self.group_by_fields,
            'view': 'FULL'
        }
        metric_list = client.execute_query('list', {'name': 'projects/' + project, **query_params})
        self.split_by_resource(metric_list['timeSeries'])
        matched = [r for r in resources if self.process_resource(r)]

        return matched

    def get_query_filter(self, resources):
        metric_filter = 'metric.type = "{}" AND '.format(self.metric)

        for r in resources:
            resource_name = jmespath.search(self.resource_key, r)
            metric_filter += '{} = "{}" OR '.format(self.metric_key, resource_name)
        metric_filter = metric_filter.rsplit(' OR ', 1)[0]
        return metric_filter

    def split_by_resource(self, metric_list):
        for m in metric_list:
            resource_name = jmespath.search(self.metric_key, m)
            self.resource_metric_dict[resource_name] = m

    def process_resource(self, resource):
        resource_metric = resource.setdefault('c7n.metrics', {})

        resource_name = jmespath.search(self.resource_key, resource)
        metric = self.resource_metric_dict.get(resource_name)
        if not metric:
            metric_value = self.missing_value
        else:
            metric_value = float(list(metric["points"][0]["value"].values())[0])

        c7n_metric_key = "%s.%s.%s" % (self.metric, self.aligner, self.reducer)
        resource_metric[c7n_metric_key] = metric

        matched = self.op(metric_value, self.value)
        return matched

    @classmethod
    def register_resources(klass, registry, resource_class):
        resource_class.filter_registry.register('metrics', klass)


gcp_resources.subscribe(GCPMetricsFilter.register_resources)
