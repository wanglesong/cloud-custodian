# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import logging

from huaweicloudsdksmn.v2 import PublishMessageRequest, PublishMessageRequestBody
from c7n.utils import type_schema, local_session
from c7n.filters import Filter
from c7n.exceptions import PolicyValidationError
from c7n_huaweicloud.provider import resources
from c7n_huaweicloud.query import QueryResourceManager, TypeInfo
from c7n_huaweicloud.actions.base import HuaweiCloudBaseAction
from huaweicloudsdkcore.exceptions import exceptions

log = logging.getLogger("custodian.huaweicloud.resources.coc")


@resources.register('coc-patch')
class CocPatch(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'coc'
        enum_spec = ('list_instance_compliant', 'instance_compliant', 'offset')
        id = 'id'
        offset_start_num = 1
        tag_resource_type = None


@CocPatch.action_registry.register("patch_non_compliant_alarm")
class PatchNonCompliantAlarm(HuaweiCloudBaseAction):
    """Alarm non compliant patch.

    :Example:

    .. code-block:: yaml

         policies:
           - name: non-compliant-patch
             resource: huaweicloud.coc
             filters:
               - type: value
                 key: status
                 value: 'non_compliant'
                 op: eq
               - type: value
                 key: report_scene
                 value: 'ECS'
                 op: eq
               - type: value
                 key: operating_system
                 value: 'CentOS'
                 op: eq
               - type: value
                 key: region
                 value: 'cn-north-4'
                 op: eq
             actions:
               - type: patch_non_compliant_alarm
                 topic_urn_list:
                   - "urn:smn:region:account-id:topic-name"
                 subject: ""
                 message: ""
    """

    schema = type_schema("patch_non_compliant_alarm",
                         required=['topic_urn_list'],
                         topic_urn_list={'type': 'array', 'items': {'type': 'string'}},
                         subject={'type': 'string'},
                         message={'type': 'string'}
                         )

    def process(self, resources):
        """Process message sending logic"""
        if not resources:
            return resources

        topic_urn_list = self.data.get('topic_urn_list', None)
        subject = self.data.get('subject', 'Patch Security Non-Compliance Alert')
        message = self.data.get('message', 'Incompliant patches are detected on the following hosts, '
                                           'Repair the patches in time.')

        if not topic_urn_list and len(topic_urn_list) < 1:
            raise PolicyValidationError("Can not create smn alarm message when parameter:topic_urn is None.")

        patch_non_compliant_data = ''
        for resource in resources:
            ecs_name = resource.get('name')
            region = resource.get('region')
            ecs_instance_id = resource.get('instance_id')
            non_compliant_count = resource.get('non_compliant_summary').get('non_compliant_count')
            patch_non_compliant_data = (f'ecs_name: {ecs_name}, ecs_instance_id: {ecs_instance_id}, '
                                        f'region: {region}, non_compliant_count: {non_compliant_count}')

        for topic_urn in topic_urn_list:
            client = local_session(self.manager.session_factory).client('smn')
            message_body = PublishMessageRequestBody(
                subject=subject,
                message=message + '\n' + patch_non_compliant_data
            )
            request = PublishMessageRequest(topic_urn=topic_urn, body=message_body)
            try:
                response = client.publish_message(request)
                log.info("[actions]-[patch_non_compliant_alarm]-The resource:[coc-patch] "
                         f"send message to {topic_urn} has succeeded, the smn message id: {response.message_id}.")
            except exceptions.ClientRequestException as e:
                log.error("[actions]-[patch_non_compliant_alarm]-The resource:[coc-patch] "
                          f"send message to {topic_urn} failed: {e.error_msg}")
                raise e


@resources.register('coc-script')
class CocScript(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'coc'
        enum_spec = ('list_scripts', 'data', 'marker')
        id = 'id'
        offset_start_num = 1
        tag_resource_type = None


@CocScript.filter_registry.register("script_non_reviewer")
class ScriptNonReviewerFilter(Filter):
    """Check if a script does not have an assigned reviewer.

    .. code-block:: yaml

      policies:
       - name: script_non_reviewer
         resource: huaweicloud.coc-script
         filters:
           - script_non_reviewer_filter
    """
    schema = type_schema('script_non_reviewer_filter')

    def process(self, resources):
        """Filter scripts without configured reviewers
        """
        if not resources:
            return resources
        filter_resources = []
        for resource in resources:
            script_list = resource.get('data', [])
            if len(script_list) == 0:
                continue
            for script in script_list:
                properties = script.get('properties', None)
                if not properties:
                    continue
                reviewers = properties.get('reviewers', [])
                if len(reviewers) == 0:
                    filter_resources.append(script)
        return filter_resources


@CocScript.action_registry.register("script_non_reviewer_alarm")
class ScriptNonReviewerAlarm(HuaweiCloudBaseAction):
    """Alarm non reviewer script.

    Used to send notification messages regarding scripts without configured reviewers,
    including script name and script ID information.

    :Example:

    .. code-block:: yaml

         policies:
           - name: script_non_reviewer_alarm
             resource: huaweicloud.coc
             filters:
               - type: value
                 key: risk_level
                 op: in
                 value:
                   - xxxx
                   - xxxx
             actions:
               - type: script_non_reviewer_alarm
                 topic_urn_list:
                   - "urn:smn:region:account-id:topic-name"
                 subject: ""
                 message: ""
    """

    schema = type_schema("script_non_reviewer_alarm",
                         required=['topic_urn_list'],
                         topic_urn_list={'type': 'array', 'items': {'type': 'string'}},
                         subject={'type': 'string'},
                         message={'type': 'string'}
                         )

    def process(self, resources):
        """Process message sending logic"""
        if not resources:
            return resources

        topic_urn_list = self.data.get('topic_urn_list', None)
        subject = self.data.get('subject', 'Script Security Non-Compliance Alert')
        message = self.data.get('message', 'The following script has been found to lack an assigned reviewer, '
                                           'which constitutes a security non-compliance. '
                                           'Please promptly assign a reviewer.')

        if not topic_urn_list and len(topic_urn_list) < 1:
            raise PolicyValidationError("Can not create smn alarm message when parameter:topic_urn is None.")

        script_non_reviewer_data = ''
        for resource in resources:
            script_id = resource.get('script_uuid')
            script_name = resource.get('name', '')
            operator = resource.get('operator', '')
            properties = resource.get('properties', '')
            risk_level = properties.get('risk_level') if not properties else ''

            script_non_reviewer_data += (f'script_id: {script_id}, script_name: {script_name}, operator: {operator}, '
                                         f'risk_level: {risk_level}\n')

        for topic_urn in topic_urn_list:
            client = local_session(self.manager.session_factory).client('smn')
            message_body = PublishMessageRequestBody(
                subject=subject,
                message=message + '\n' + script_non_reviewer_data
            )
            request = PublishMessageRequest(topic_urn=topic_urn, body=message_body)
            try:
                response = client.publish_message(request)
                log.info("[actions]-[script_non_reviewer_alarm]-The resource:[coc-script] "
                         f"send message to {topic_urn} has succeeded, the smn message id: {response.message_id}.")
            except exceptions.ClientRequestException as e:
                log.error("[actions]-[script_non_reviewer_alarm]-The resource:[coc-script] "
                          f"send message to {topic_urn} failed: {e.error_msg}")
                raise e
