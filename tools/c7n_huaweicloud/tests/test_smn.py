# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from huaweicloud_common import BaseTest


class SmnTest(BaseTest):

    def test_topic_query(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_query",
            "resource": "huaweicloud.smn-topic"
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 2)
        self.assertEqual(resources[0]['name'], "tt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f53")

    def test_topic_filter_lts_enabled(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_filter_lts_enabled",
            "resource": "huaweicloud.smn-topic",
            "filters": [
                {
                    "type": "topic-lts",
                    "enabled": True
                }
            ]
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['name'], "tt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f53")

    def test_topic_filter_lts_enabled_false(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_filter_lts_enabled_false",
            "resource": "huaweicloud.smn-topic",
            "filters": [
                {
                    "type": "topic-lts",
                    "enabled": False
                }
            ]
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['name'], "ttt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f54")

    def test_topic_filter_access_user(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_filter_access_user",
            "resource": "huaweicloud.smn-topic",
            "filters": [
                {
                    "type": "topic-access",
                    "effect": "Allow",
                    "user": "2284f67d00db4d5896511837ef2f7366"
                }
            ]
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['name'], "ttt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f54")

    def test_topic_filter_access_user_all(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_filter_access_user_all",
            "resource": "huaweicloud.smn-topic",
            "filters": [
                {
                    "type": "topic-access",
                    "effect": "Allow",
                    "user": "*"
                }
            ]
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['name'], "tt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f53")

    def test_topic_filter_access_service(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_filter_access_service",
            "resource": "huaweicloud.smn-topic",
            "filters": [
                {
                    "type": "topic-access",
                    "effect": "Allow",
                    "service": "dws"
                }
            ]
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['name'], "ttt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f54")

    def test_topic_filter_access_effect(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_filter_access_effect",
            "resource": "huaweicloud.smn-topic",
            "filters": [
                {
                    "type": "topic-access",
                    "effect": "Deny",
                    "organization": "o-bf966fe82ebb4d35d68b791729228788"
                                    "/r-001ebf32880a13eabfc8e1c37eee3ae9"
                                    "/ou-0dbfffe92fd92ddb35feff9b4079459c"
                }
            ]
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['name'], "ttt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f54")

    def test_topic_filter_tag(self):
        factory = self.replay_flight_data('smn_topic_query')
        p = self.load_policy({
            "name": "test_topic_filter_tag",
            "resource": "huaweicloud.smn-topic"
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 2)
        self.assertEqual(resources[0]['name'], "tt")
        self.assertEqual(resources[0]['topic_id'], "d745b6a999a049c09446fea0ecac8f53")
        self.assertEqual(len(resources[0]['tags']), 2)

    def test_topic_actions_delete_allow_all_user_access(self):
        factory = self.replay_flight_data('smn_topic_access_query')
        p = self.load_policy({
            "name": "test_topic_filter_tag",
            "resource": "huaweicloud.smn-topic",
            "actions": [
                {
                    "type": "delete-allow-all-user-access"
                }
            ]
        }, session_factory=factory)
        resources = p.run()
        self.assertEqual(len(resources), 3)
        self.assertFalse(resources[0]['access_policy'].__contains__("*"))
        self.assertFalse(resources[1]['access_policy'].__contains__("*"))
        self.assertTrue(resources[2]['access_policy'] is None)
