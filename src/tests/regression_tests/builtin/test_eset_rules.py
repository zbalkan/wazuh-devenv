#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from eset.ini
class TestEsetRules(unittest.TestCase):

    def test_eset_threat_event_rules_group(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"Threat_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42002')
        self.assertEqual(response.rule_level, 3)


    def test_eset_firewall_aggregated_rules_group(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"FirewallAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42003')
        self.assertEqual(response.rule_level, 3)


    def test_eset_hips_aggregated_rules_group(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42004')
        self.assertEqual(response.rule_level, 3)


    def test_eset_audit_rules_group(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"Audit_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42005')
        self.assertEqual(response.rule_level, 2)


    def test_eset_enterprise_inspector_alert_rules_group(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"EnterpriseInspectorAlert_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Information","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42006')
        self.assertEqual(response.rule_level, 3)


    def test_eset_warning_severity(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Warning","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42007')
        self.assertEqual(response.rule_level, 5)


    def test_eset_error_severity(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Error","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42008')
        self.assertEqual(response.rule_level, 7)


    def test_eset_critical_severity(self) -> None:
        log = r'''
May  6 10:59:37 XXXXX ERAServer[5032]: {"event_type":"HipsAggregated_Event","ipv4":"XXX.XXX.XXX.XXX","hostname":"XXXXX","source_uuid":"9416183d-3XX3-4776-9783-9532a3a027bb","occured":"06-May-2021 09:59:37","severity":"Critical","domain":"Domain group","action":"Login attempt","target":"a49d257e-ecc6-4063-95c6-5eb5e6b3e5df","detail":"Authenticating domain user 'XXXXXXXX'.","user":"","result":"Success"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'eset-bsd')
        self.assertEqual(response.rule_id, '42009')
        self.assertEqual(response.rule_level, 12)

