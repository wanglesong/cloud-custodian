# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import uuid
import time

from huaweicloudsdkkms.v2 import (EnableKeyRotationRequest, OperateKeyRequestBody,
                                  DisableKeyRotationRequest, EnableKeyRequest,
                                  DisableKeyRequest, CreateKeyRequest, CreateKeyRequestBody,
                                  ListAliasesRequest, CreateAliasRequest,
                                  CreateAliasRequestBody, ListKeysRequest, ListKmsByTagsRequest,
                                  ListKmsByTagsRequestBody)

from c7n import exceptions
from c7n.filters import ValueFilter
from c7n.utils import type_schema, local_session
from c7n_huaweicloud.actions.base import HuaweiCloudBaseAction
from c7n_huaweicloud.provider import resources
from c7n_huaweicloud.query import QueryResourceManager, TypeInfo

log = logging.getLogger("custodian.huaweicloud.resources.kms")


@resources.register('kms')
class Kms(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'kms'
        enum_spec = ("list_keys", 'key_details', 'offset')
        id = 'key_id'
        tag_resource_type = 'kms'
        config_resource_support = True

    def get_resources(self, resource_ids):
        allResources = self.get_api_resources(resource_ids)
        resources = []
        for resource in allResources:
            if resource["key_id"] in resource_ids:
                resources.append(resource)
        return resources

    def _fetch_resources(self, query):
        return self.get_api_resources(query)

    def get_api_resources(self, resource_ids):
        session = local_session(self.session_factory)
        client = session.client(self.resource_type.service)
        resources = []
        resourceTagDict = {}
        offset, limit = 0, 1000
        isQueryTags = True

        request = ListKeysRequest()
        request.key_spec = "ALL"
        try:
            response = client.list_keys(request)
            details = response.key_details
            if len(details) == 0:
                log.debug("[filter]-the filter list_keys,the resource:resourceType:KMS "
                          "list_keys details is empty")
                return details

            if hasattr(details[0], "tags"):
                log.debug("[filter]-the filter list_keys,the resource:resourceType:KMS "
                          "list_keys tags is empty")
                isQueryTags = False
        except Exception as e:
            log.error(
                "[filter]- the filter list_keys query the service:kms/list-keys "
                "the resource:resourceType:KMS "
                "is failed,cause={}".format(e.error_msg))
            raise e

        if isQueryTags:
            while True:
                requestTag = ListKmsByTagsRequest()
                requestTag.resource_instances = "resource_instances"
                requestTag.body = ListKmsByTagsRequestBody(
                    action="filter",
                    offset=str(offset),
                    limit=str(limit)
                )

                try:
                    responseTag = client.list_kms_by_tags(requestTag)
                    tagResources = responseTag.resources
                    if len(tagResources) == 0:
                        log.debug("[filter]-list_kms_by_tags,query the "
                                  "service:kms/service_instance/action,"
                                  "the resource:resourceType:KMS "
                                  "list_kms_by_tags response is empty")
                    for tagResource in tagResources:
                        resourceTagDict[tagResource.resource_id] = tagResource.to_dict().get('tags')

                except Exception as e:
                    log.error(
                        "[filter]-list_kms_by_tags,query the service:kms/service_instance/action, "
                        "the resource:resourceType:KMS "
                        "list_kms_by_tags is failed,cause={}".format(e.error_msg))

                    raise e

                offset += limit

                if not responseTag.total_count or offset >= len(responseTag.resources):
                    break
            default = []
            for detail in details:
                dict = detail.to_dict()
                dict["tags"] = resourceTagDict.get(detail.key_id, default)
                dict["id"] = detail.key_id
                resources.append(dict)
            return resources
        else:
            return details


@Kms.action_registry.register("enable_key_rotation")
class rotationKey(HuaweiCloudBaseAction):
    """rotation kms key.

    :Example:

    .. code-block:: yaml

policies:
  - name: enable_key_rotation
    resource: huaweicloud.kms
    mode:
      type: huaweicloud-periodic
      xrole: fgs_admin
      enable_lts_log: true
      log_level: INFO
      schedule: '1m'
      schedule_type: Rate
    filters:
        - type: value
          key: key_rotation_enabled
          value: "False"
        - type: value
          key: domain_id
          value: "537f650fb2be4ca3a511f25d8defd3b0"
        - type: value
          key: default_key_flag
          value: "0"
        - type: value
          key: keystore_id
          value: "0"
        - type: value
          key: key_state
          value: "2"
    actions:
      - enable_key_rotation
    """

    schema = type_schema("enable_key_rotation")

    def perform_action(self, resource):
        supportList = {"AES_256", "SM4"}
        resourceId = resource["key_id"]
        if (resource["default_key_flag"] == "0" and resource["key_spec"]
                in supportList and resource["keystore_id"] == "0"
                and resource["key_state"] in {"2"}):
            client = self.manager.get_client()
            request = EnableKeyRotationRequest()
            request.body = OperateKeyRequestBody(
                key_id=resource["key_id"],
                sequence=uuid.uuid4().hex
            )
            try:
                client.enable_key_rotation(request)
                log.info("[action]-enable_key_rotation the resource:resourceType:KMS "
                         "with resourceId={},"
                         "success"
                         .format(resourceId))
            except Exception as e:
                if e.status_code == 400:
                    log.info(
                        "[action]-enable_key_rotation the resource:resourceType:KMS with "
                        "resourceId={} "
                        "is failed, cause={}".format(resourceId, e.error_msg))
                else:
                    log.error(
                        "[action]-enable_key_rotation the resource:resourceType:KMS "
                        "with resourceId={} "
                        "is failed, cause={}".format(resourceId, e.error_msg))
                    raise e

        else:
            log.info("skip enable_key_rotation the resourceType:KMS resourceId={},"
                     "The key does not meet the conditions for "
                     "enabling rotation.The conditions for ending the key are:"
                     "the key is not the default key,is not a shared "
                     "key,and the algorithm is SM4 or AES_256".format(resourceId))


@Kms.action_registry.register("disable_key_rotation")
class disableRotationKey(HuaweiCloudBaseAction):
    """rotation kms key.

    :Example:

    .. code-block:: yaml

policies:
  - name: enable_key_rotation
    resource: huaweicloud.kms
    filters:
        - type: value
          key: key_rotation_enabled
          value: "false"
        - type: value
          key: domain_id
          value: "537f650fb2be4ca3a511f25d8defd3b0"
    actions:
      - disable_key_rotation
    """

    schema = type_schema("disable_key_rotation")

    def perform_action(self, resource):
        supportList = {"AES_256", "SM4"}
        resourceId = resource["key_id"]
        if (resource["default_key_flag"] == "0" and resource["key_spec"]
                in supportList and resource["keystore_id"] == "0"
                and resource["key_state"] in {"2"}):
            client = self.manager.get_client()
            request = DisableKeyRotationRequest()
            request.body = OperateKeyRequestBody(
                key_id=resource["key_id"],
                sequence=uuid.uuid4().hex
            )
            try:
                client.disable_key_rotation(request)
                log.info(
                    "[action]-disable_key_rotation the resource:resourceType:KMS with "
                    "resourceId={} success".format(resourceId))
            except Exception as e:
                if e.status_code == 400:
                    log.info(
                        "[action]-disable_key_rotation the resource:resourceType:KMS with "
                        "resourceId={} "
                        "is failed, cause={}".format(resourceId, e.error_msg))
                else:
                    log.error(
                        "[action]-disable_key_rotation the resource:resourceType:KMS "
                        "with resourceId={} "
                        "is failed, cause={}".format(resourceId, e.error_msg))
                    raise e

            else:
                log.info("skip disable_key_rotation the resourceType:KMS resourceId={},"
                         "The key does not meet the conditions for "
                         "enabling rotation.The conditions for ending the key are:"
                         "the key is not the default key,is not a shared "
                         "key,and the algorithm is SM4 or AES_256".format(resourceId))


@Kms.action_registry.register("enable_key")
class enableKey(HuaweiCloudBaseAction):
    """rotation kms key.

    :Example:

    .. code-block:: yaml

    policies:
      - name: enable_key
        resource: huaweicloud.kms
        filters:
          - type: value
            key: key_state
            value: "3"
        actions:
          - enable_key
    """

    schema = type_schema("enable_key")

    def perform_action(self, resource):
        client = self.manager.get_client()
        resourceId = resource["key_id"]
        if (resource["default_key_flag"] == "0" and resource["keystore_id"] == "0"
                and resource["key_state"] in {"3"}):
            request = EnableKeyRequest()
            request.body = OperateKeyRequestBody(
                key_id=resource["key_id"],
                sequence=uuid.uuid4().hex
            )
            try:
                response = client.enable_key(request)
                log.info(
                    "[action]-enable_key the resource:resourceType:KMS with "
                    "resourceId={} success".format(resourceId))
            except Exception as e:
                if e.status_code == 400:
                    log.info(
                        "[action]-enable_key the resource:resourceType:KMS with "
                        "resourceId={} "
                        "is failed, cause={}".format(resourceId, e.error_msg))
                else:
                    raise e
        else:
            log.info("skip enable_key the resourceType:KMS resourceId={}".format(resourceId))
        return response


@Kms.action_registry.register("disable_key")
class disableKey(HuaweiCloudBaseAction):
    """rotation kms key.

    :Example:

    .. code-block:: yaml

    policies:
      - name: disable_key
        resource: huaweicloud.kms
        filters:
          - type: value
            key: key_state
            value: "2"
        actions:
          - disable_key
    """

    schema = type_schema("disable_key")

    def perform_action(self, resource):
        client = self.manager.get_client()
        resourceId = resource["key_id"]
        response = ""
        if (resource["default_key_flag"] == "0" and resource["keystore_id"] == "0"
                and resource["key_state"] in {"2"}):
            request = DisableKeyRequest()
            request.body = OperateKeyRequestBody(
                key_id=resource["key_id"],
                sequence=uuid.uuid4().hex
            )
            try:
                response = client.disable_key(request)
                log.info(
                    "[action]-disable_key the resource:resourceType:KMS with "
                    "resourceId={} success".format(resourceId))
            except Exception as e:
                if e.status_code == 400:
                    log.info(
                        "[action]-disable_key the resource:resourceType:KMS with "
                        "resourceId={} "
                        "is failed, cause={}".format(resourceId, e.error_msg))
                else:
                    raise e
        else:
            log.info("skip disable_key the resourceType:KMS resourceId={}".format(resourceId))
        return response


@Kms.action_registry.register("create-key-with-alias")
class createKey(HuaweiCloudBaseAction):
    """rotation kms key.

    :Example:

    .. code-block:: yaml

policies:
  - name: create-key-with-alias
    resource: huaweicloud.kms
    mode:
      type: huaweicloud-periodic
      xrole: fgs_admin
      enable_lts_log: true
      log_level: INFO
      schedule: '1m'
      schedule_type: Rate
    actions:
      - type: create-key-with-alias
        key_aliases: ["test"]
        obs_url: "https://custodian0527.obs.sa-brazil-1.myhuaweicloud.com/kms.txt"

    """

    schema = type_schema("create-key-with-alias",
                         key_aliases={"type": "array"},
                         obs_url={"type": "string"})

    def process(self, resource):

        client = self.manager.get_client()
        all_key_aliases = set()
        key_aliases = self.data.get("key_aliases", [])
        all_key_aliases.update(key_aliases)
        obs_url = self.data.get("obs_url", None)
        obs_client = local_session(self.manager.session_factory).client("obs")
        if not key_aliases and obs_url is None:
            log.info(
                "[action]-create-key-with-alias the resource:resourceType:KMS "
                "is failed, cause=key_aliases or obs_url is required")
            return []
        if obs_url is not None and obs_url != '':
            # 1. 提取第一个变量：从 "https://" 到最后一个 "obs" 的部分
            protocol_end = len("https://")
            # 去除协议头后的完整路径
            path_without_protocol = obs_url[protocol_end:]
            obs_bucket_name = self.get_obs_name(path_without_protocol)
            obs_server = self.get_obs_server(path_without_protocol)
            obs_file = self.get_file_path(path_without_protocol)
            obs_client.server = obs_server
            try:
                resp = obs_client.getObject(bucketName=obs_bucket_name,
                                            objectKey=obs_file,
                                            loadStreamInMemory=True)
                if resp.status < 300:
                    log.debug("[action]-create-key-with-alias:query obs url getobject success")
                    all_key_aliases.update(json.loads(resp.body.buffer)['obs_key_aliases'])
                else:
                    log.error(f"[action]-create-key-with-alias query obs fail: {resp.errorCode}, "
                              f"{resp.errorMessage}")
                    return []
            except exceptions.ClientRequestException as e:
                log.error("[action]-create-key-with-alias:query obs url getobject failded,msg={}"
                          .format(e.error_msg))
                raise e

        try:
            listAliasesRequest = ListAliasesRequest()
            listAliasResponse = client.list_aliases(listAliasesRequest)
            log.debug("[action]-create-key-with-alias:query list_aliases success")
            arr = set()
            for realAlias in listAliasResponse.body[0].aliases:
                arr.add(realAlias.alias.replace('alias/', ''))
        except exceptions.ClientRequestException as e:
            log.error("[action]-create-key-with-alias:query obs url list_aliases failded,msg={}"
                      .format(e.error_msg))
            raise e
        if len(all_key_aliases) != 0:
            for alias in all_key_aliases:
                if alias not in arr:
                    timestamp = int(time.time())
                    keyName = str(timestamp)
                    createKeyRequest = CreateKeyRequest()
                    createKeyRequest.body = CreateKeyRequestBody(
                        key_alias=keyName
                    )
                    try:
                        createKeyResponse = client.create_key(createKeyRequest)
                        log.debug("[action]-create-key-with-alias:query create_key success")
                        createKeyId = createKeyResponse.key_info.key_id
                        createAliasRequest = CreateAliasRequest()
                        createAliasRequest.body = CreateAliasRequestBody(
                            key_id=createKeyId,
                            alias="alias/" + alias
                        )
                        client.create_alias(createAliasRequest)
                        log.info("[action]-create-key-with-alias:query create_alias "
                                 "with resourceID={} success".format(createKeyId))
                        time.sleep(1)
                    except Exception as e:
                        log.error("[action]-create-key-with-alias:query obs url "
                                  "create_alias failded,msg={}"
                                  .format(e.error_msg))
                        raise e

    def perform_action(self, resource):
        return super().perform_action(resource)

    def get_obs_name(self, obs_url):
        # 找到最后一个 ".obs" 的索引位置
        last_obs_index = obs_url.rfind(".obs")
        return obs_url[:last_obs_index]

    def get_obs_server(self, obs_url):
        # 找到最后一个 ".obs" 的索引位置
        last_obs_index = obs_url.rfind(".obs")
        remaining_after_obs = obs_url[last_obs_index:]
        split_res = remaining_after_obs.split("/", 1)
        return split_res[0].lstrip(".")

    def get_file_path(self, obs_url):
        # 找到最后一个 ".obs" 的索引位置
        last_obs_index = obs_url.rfind(".obs")
        remaining_after_obs = obs_url[last_obs_index:]
        split_res = remaining_after_obs.split("/", 1)
        return split_res[1]


@Kms.filter_registry.register("all_keys_disable")
class instanceDisable(ValueFilter):
    '''
    policies:
      - name: all_keys_disable
        resource: huaweicloud.kms
        filters:
          - type: all_keys_disable
            key: "key_state"
            value: "2"
    '''
    schema = type_schema("all_keys_disable",
                         rinherit=ValueFilter.schema)
