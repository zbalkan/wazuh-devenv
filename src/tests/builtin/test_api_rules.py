#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from api.ini
class TestApiRules(unittest.TestCase):

    def test_api_bad_request(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 400'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '410')
        self.assertEqual(response.rule_level, 4)


    def test_api_unauthorized(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 401'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '411')
        self.assertEqual(response.rule_level, 8)


    def test_apis_response_code_returned_error_permission_denied(self) -> None:
        log = '''2021/10/04 15:23:55 INFO: unknown_user 172.18.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.001s: 403'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '412')
        self.assertEqual(response.rule_level, 7)


    def test_resource_not_found(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 404'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '413')
        self.assertEqual(response.rule_level, 4)


    def test_invalid_http_method(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 405'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '414')
        self.assertEqual(response.rule_level, 4)


    def test_invalid_content_type(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 406'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '415')
        self.assertEqual(response.rule_level, 4)


    def test_maximum_request_body_size_exceeded(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 413'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '416')
        self.assertEqual(response.rule_level, 4)


    def test_max_number_of_requests_per_minute_reached(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 429'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '417')
        self.assertEqual(response.rule_level, 7)


    def test_internal_error(self) -> None:
        log = '''2021/10/05 10:33:18 INFO: testing 172.21.0.1 "GET /agents/upgrade_result" with parameters {"agents_list": "bad_id"} and body {} done in 0.006s: 500'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '418')
        self.assertEqual(response.rule_level, 4)


    def test_apis_put_method_event(self) -> None:
        log = '''2021/04/20 16:00:35 INFO: wazuh 127.0.0.1 "PUT /agents/group" with parameters {"group_id": "group1", "agents_list":629,650,654,682"} and body {} done in 0.075s: 200'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '407')
        self.assertEqual(response.rule_level, 5)


    def test_apis_get_method_event_success(self) -> None:
        log = '''2021/10/05 10:33:14 INFO: testing 172.21.0.1 "GET /agents/stats/distinct" with parameters {"fields": "os.name"} and body {} done in 0.009s: 200'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '406')
        self.assertEqual(response.rule_level, 4)


    def test_api_post_method_event_success(self) -> None:
        log = '''2021/10/07 10:46:00 INFO: wazuh-wui 172.16.1.1 "POST /groups" with parameters {} and body {"group_id": "NewGroup_1"} done in 0.009s: 200'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '409')
        self.assertEqual(response.rule_level, 5)


    def test_api_delete_method_event_success(self) -> None:
        log = '''2021/10/07 10:32:33 INFO: unknown_user 172.16.1.1 "DELETE /agents" with parameters {} and body {} done in 0.001s: 200'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '408')
        self.assertEqual(response.rule_level, 7)


    def test_api_info_informative_event(self) -> None:
        log = '''2021/10/05 10:30:21 INFO: Generated private key file in WAZUH_PATH/api/configuration/ssl/server.key'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api-info')
        self.assertEqual(response.rule_id, '421')
        self.assertEqual(response.rule_level, 3)


    def test_api_info_warning_event(self) -> None:
        log = '''2021/10/04 15:23:55 WARNING: something wrong happened'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api-info')
        self.assertEqual(response.rule_id, '422')
        self.assertEqual(response.rule_level, 5)


    def test_api_info_error_event(self) -> None:
        log = '''2021/10/04 15:23:55 ERROR: Something bad happened'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api-info')
        self.assertEqual(response.rule_id, '423')
        self.assertEqual(response.rule_level, 8)


    def test_api_info_ip_blocked(self) -> None:
        log = '''2021/10/04 15:23:55 ERROR: IP blocked due to exceeded number of logins attempts: 172.18.0.1'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api-info')
        self.assertEqual(response.rule_id, '428')
        self.assertEqual(response.rule_level, 10)


    def test_api_info_critical_event(self) -> None:
        log = '''2021/10/05 10:30:21 CRITICAL: Generated private key file in WAZUH_PATH/api/configuration/ssl/server.key'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api-info')
        self.assertEqual(response.rule_id, '424')
        self.assertEqual(response.rule_level, 12)


    def test_api_authentication_success(self) -> None:
        log = '''2021/10/05 10:33:15 INFO: testing 172.21.0.1 "POST /security/user/authenticate" with parameters {} and body {} done in 0.354s: 200'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '426')
        self.assertEqual(response.rule_level, 4)


    def test_api_authentication_success_with_hash(self) -> None:
        log = '''2022/02/03 10:37:36 INFO: wazuh (d8466023fdec3f1310679989d8827eee) 172.20.0.1 "POST /security/user/authenticate/run_as" with parameters {"raw": "true"} and body {"user_name": "test", "is_reserved": false, "is_hidden": false, "is_internal_user": true, "user_requested_tenant": "__user__", "backend_roles": [""], "custom_attribute_names": [], "tenants": {"test": true, "global_tenant": true, "admin_tenant": true}, "roles": ["own_index", "all_access"]} done in 0.309s: 200'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '426')
        self.assertEqual(response.rule_level, 4)


    def test_api_authentication_failure(self) -> None:
        log = '''2021/10/05 10:33:15 INFO: testing 172.21.0.1 "POST /security/user/authenticate" with parameters {} and body {} done in 0.354s: 400'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'wazuh-api')
        self.assertEqual(response.rule_id, '427')
        self.assertEqual(response.rule_level, 7)

