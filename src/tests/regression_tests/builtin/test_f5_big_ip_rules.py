#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from f5_big_ip.ini
class TestF5BigIpRules(unittest.TestCase):

    def test_high_demand_traffic(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010251:0: Virtual componentName exceeded configured rate limit.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65261')
        self.assertEqual(response.rule_level, 9)


    def test_syn_flood_attack(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010343:0: Syncookie SW mode activated, server = 1.1.1.1:4000
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65262')
        self.assertEqual(response.rule_level, 13)


    def test_stopped_throttling_traffic(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 011e0001:0: Limiting componentName from 40 to 40 packets/sec for traffic-group componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65263')
        self.assertEqual(response.rule_level, 9)


    def test_syn_cookie_threshold_is_reached(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010038:0: Syncookie counter 40 exceeded vip threshold %u for virtual = 1.1.1.1:4000
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65264')
        self.assertEqual(response.rule_level, 9)


    def test_detected_a_syncookie_dos_attack(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010240:0: Syncookie HW mode activated, server = 1.1.1.1:4000, HSB modId = 40
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65265')
        self.assertEqual(response.rule_level, 13)


    def test_ongoing_ddos_attack(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010329:0: BDoS: (TMM) Signature componentName: threshold_mode=componentName detection=%u mitigation_curr=%llu
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65266')
        self.assertEqual(response.rule_level, 13)


    def test_created_updated_afm_bdos_dynamic_signature_by_the_afm_bdosd_daemon_during_an_attack(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010302:0: BDoS: (TMM) componentName signature (componentName) for context componentName at idx %u (detection=%u mitigation=%u state=componentName transient=componentName retired=componentName).
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65267')
        self.assertEqual(response.rule_level, 11)


    def test_number_of_allowed_new_connections_per_second_for_pool_member_has_been_exceeded(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010250:0: Pool member %A:%u exceeded configured rate limit.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65268')
        self.assertEqual(response.rule_level, 10)


    def test_syncookie_dos_attack_has_stopped(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010241:0: Syncookie HW mode exited, server = 1.1.1.1:4000, HSB modId = 40 from componentName.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65269')
        self.assertEqual(response.rule_level, 6)


    def test_syncookie_counter_exceeded_vip_threshold(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010056:0: Syncookie counter 40 exceeded vip threshold %u for virtual = componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65270')
        self.assertEqual(response.rule_level, 10)


    def test_syn_cookie_state_exited(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010344:0: Syncookie SW mode exited, server = 1.1.1.1:4000
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65271')
        self.assertEqual(response.rule_level, 2)


    def test_sslv2_is_no_longer_supported_and_has_been_removed(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01071bee:0: SSLv2 is no longer supported and has been removed. The 'sslv2' keyword in the cipher string has been ignored.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65272')
        self.assertEqual(response.rule_level, 4)


    def test_user_is_prevented_from_doing_things_they_are_not_authorized_to_do(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01070822:0: "Access Denied: componentName"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65273')
        self.assertEqual(response.rule_level, 5)


    def test_mcpd_has_detected_that_sync_traffic_is_being_sent_over_a_vlan_that_is_not_the_correct_one(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01071bd1:0: Inbound CMI connection from IP (componentName) denied because it came from VLAN (componentName), not from expected VLAN (componentName).
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65274')
        self.assertEqual(response.rule_level, 9)


    def test_too_many_sip_media_sessions_have_been_established_for_the_current_configuration(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01860017:0: MR_SIP: Too many media sessions 40 / 40. Error Code 40
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65275')
        self.assertEqual(response.rule_level, 10)


    def test_critical_error_for_tmm_it_restarts_attempts_to_reconnect_will_be_made_after_that(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01010020:0: MCP Connection componentName, exiting
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65276')
        self.assertEqual(response.rule_level, 10)


    def test_errors_could_be_caused_by_a_broken_feature_or_critical_system_errors(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01071d0b:0: adm: componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65277')
        self.assertEqual(response.rule_level, 12)


    def test_the_hal_daemon_might_not_be_able_to_correctly_identify_the_platform_or_publish_the_hardware_abstraction_configuration_at_startup_or_has_encountered_a_critical_failure_during_normal_operation_1(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 012a0002:0: "LIBHAL reporting critical conditions"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65278')
        self.assertEqual(response.rule_level, 10)


    def test_the_hal_daemon_might_not_be_able_to_correctly_identify_the_platform_or_publish_the_hardware_abstraction_configuration_at_startup_or_has_encountered_a_critical_failure_during_normal_operation_2(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 012a0003:0: LIBHAL reporting error conditions
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65278')
        self.assertEqual(response.rule_level, 10)


    def test_hardware_sensor_critical_alarm(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 012a0013:0: Blade 40 hardware sensor critical alarm: componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65279')
        self.assertEqual(response.rule_level, 13)


    def test_aom_has_indicated_that_a_temperature_sensor_has_crossed_a_critical_level_threshold(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 012a0031:0: componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65280')
        self.assertEqual(response.rule_level, 12)


    def test_aom_has_indicated_that_a_fan_sensor_has_crossed_a_critical_threshold(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 012a0037:0: componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65281')
        self.assertEqual(response.rule_level, 12)


    def test_aom_has_indicated_that_a_power_sensor_has_crossed_a_critical_threshold(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 012a0043:0: componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65282')
        self.assertEqual(response.rule_level, 12)


    def test_critical_error_that_prevents_the_broadcom_switch_from_operating_at_the_proper_configuration_required_by_big_ip(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 012c0011:0: BCM56XXD SDK error
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65283')
        self.assertEqual(response.rule_level, 12)


    def test_critical_errors_in_communication_between_tmm_threads_specifically_by_mpi_proxy(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01340003:0: Cluster error: componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65284')
        self.assertEqual(response.rule_level, 10)


    def test_serious_issue_preventing_the_guest_from_starting_or_shutting_down(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01510003:0: componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65285')
        self.assertEqual(response.rule_level, 9)


    def test_critical_the_big_ip_system_is_not_allowed_not_to_go_active_1(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01550004:0: Critical:
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65286')
        self.assertEqual(response.rule_level, 12)


    def test_critical_the_big_ip_system_is_not_allowed_not_to_go_active_2(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01550005:0: Critical:
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65286')
        self.assertEqual(response.rule_level, 12)


    def test_critical_the_big_ip_system_is_not_allowed_not_to_go_active_3(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01550006:0: Critical:
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65286')
        self.assertEqual(response.rule_level, 12)


    def test_critical_the_errdefsd_daemon_is_out_of_memory(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01940007:0: "Failed to allocate the errdefs tmconf handle!"
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65287')
        self.assertEqual(response.rule_level, 7)


    def test_critical_the_file_platform_isnt_found_and_licensing_logic_cannot_determine_the_platform_type(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01a70028:0: The platform was not found in componentName.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65288')
        self.assertEqual(response.rule_level, 7)


    def test_bot_defense_1(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01071d94:0: Bot Defense Profile (componentName) Micro Service (componentName): Missing required field (componentName).
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65289')
        self.assertEqual(response.rule_level, 3)


    def test_bot_defense_2(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 01071d9e:0: Bot defense anomaly componentName not found.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65289')
        self.assertEqual(response.rule_level, 3)


    def test_tcp_dump(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 013e0002:0: Tcpdump stopping on %la:%u from %la:%u
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65290')
        self.assertEqual(response.rule_level, 2)


    def test_tcp_dump_remote_session(self) -> None:
        log = r'''
May  5 04:26:19 hostname type process[20175]: 013e0005:0: Tcpdump starting remote to %A from %A
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65291')
        self.assertEqual(response.rule_level, 3)


    def test_asm_error(self) -> None:
        log = r'''
May  4 13:42:12 some.host.name crit server_handler.pl[24895]: 01310027:2: ASM subsystem error (asm_config_server.pl,(eval)): Couldn't pass call to async process - ignoring
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65292')
        self.assertEqual(response.rule_level, 7)


    def test_asm_illegal_action(self) -> None:
        log = r'''
May  4 18:23:02 some.host.name ASM: CEF:0|F5|ASM|14.1.2|Illegal HTTP status in response|Illegal HTTP status in response|2|dvchost=some.host.name dvc=192.168.1.000 cs1=/Common/webportal-waf-policy cs1Label=policy_name cs2=/Common/webportal-waf-policy cs2Label=http_class_name deviceCustomDate1=May 03 2021 16:57:44 deviceCustomDate1Label=policy_apply_date externalId=15489460216395818345 act=alerted cn1=409 cn1Label=response_code src=00.00.00.00 spt=59270 dst=111.1111.11.1 dpt=443 requestMethod=GET app=HTTPS cs5=22.22.22.22 cs5Label=x_forwarded_for_header_value rt=May 04 2021 18:23:02 deviceExternalId=0 cs4=Information Leakage cs4Label=attack_type cs6=N/A cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4= c6a4Label=ip_address_intelligence msg=N/A suid=2b2f405ccde7b7ed suser=N/A cn2=1 cn2Label=violation_rating cn3=0 cn3Label=device_id microservice=N/A request=/some/path cs3Label=full_request cs3=GET /other/path HTTP/1.1\r\nHost: some.host\r\nConnection: keep-alive\r\nsec-ch-ua: " Not A;Brand";v\="99", "Chromium";v\="90", "Google Chrome";v\="90"\r\nsec-ch-ua-mobile: ?0\r\nX-AUSERNAME: auser.g\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36\r\nContent-Type: application/json\r\nAccept: application/json, text/javascript, */*; q\=0.01\r\nX-Requested-With: XMLHttpRequest\r\nX-AUSERID: 1516\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: cors\r\nSec-Fetch-Dest: empty\r\nReferer: https://some.url?until\=refs%2Fheads%2Fgcp_migration_stage\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-GB,en-US;q\=0.9,en;q\=0.8\r\nCookie: _atl_bitbucket_remember_me\=M2ExMjNiMDE5MDExMTU1MTg2NzZjMGEwOTVkMWUwY2I0NTk5ZDUxMjo3MzA5NzM2NmVmMWEwYTRlNzIxMjdhYjFjYTEyN2I3NDAwMWE5M2U2; JSESSIONID\=9B114064A2D6E2CC7693BB809D66F136; TS01e7480f\=012bb8697ce2411b8d331492ed24011b153e498024e63bf863baf9f23364ced5fd2cd43bc3739eaad01a5225f494649800c636a4889315f38d7febb1900a774eb2cfa0c6788a91c93eab0ff7a4e61eb422fe089b57\r\nX-Forwarded-For: 00.0.000.110\r\n\r\n#015
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip-cef')
        self.assertEqual(response.rule_id, '65294')
        self.assertEqual(response.rule_level, 12)


    def test_asm_sql_injection(self) -> None:
        log = r'''
May  5 01:34:01 lb1.corp.ovo.id ASM: CEF:0|F5|ASM|14.1.2|200002273|SQL-INJ exec()|5|dvchost=lb1.corp.ovo.id dvc=192.168.10.4 cs1=/Common/www.ovo.id-waf-policy cs1Label=policy_name cs2=/Common/www.ovo.id-waf-policy cs2Label=http_class_name deviceCustomDate1=Apr 30 2021 07:40:41 deviceCustomDate1Label=policy_apply_date externalId=15489460216395963001 act=blocked cn1=0 cn1Label=response_code src=167.71.70.165 spt=13370 dst=10.50.72.35 dpt=443 requestMethod=GET app=HTTPS cs5=167.71.70.165 cs5Label=x_forwarded_for_header_value rt=May 05 2021 01:34:00 deviceExternalId=0 cs4=SQL-Injection cs4Label=attack_type cs6=NL cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4= c6a4Label=ip_address_intelligence msg=N/A suid=0 suser=N/A cn2=5 cn2Label=violation_rating cn3=0 cn3Label=device_id microservice=N/A request=/solr/atom/select?q\=1&&wt\=velocity&v.template\=custom&v.template.custom\=%23set($x\=%27%27)+%23set($rt\=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr\=$x.class.forName(%27java.lang.Character%27))+%23set($str\=$x.class.forName(%27java.lang.String%27))+%23set($ex\=$rt.getRuntime().exec(%27cat%20/etc/passwd%27))+$ex.waitFor()+%23set($out\=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end cs3Label=full_request cs3=GET /solr/atom/select?q\=1&&wt\=velocity&v.template\=custom&v.template.custom\=%23set($x\=%27%27)+%23set($rt\=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr\=$x.class.forName(%27java.lang.Character%27))+%23set($str\=$x.class.forName(%27java.lang.String%27))+%23set($ex\=$rt.getRuntime().exec(%27cat%20/etc/passwd%27))+$ex.waitFor()+%23set($out\=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end HTTP/1.0\r\nHost: upgrade.ovo.id\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q\=0.9,*/*;q\=0.8\r\nAccept-Language: en-US,en;q\=0.5\r\nX-Cnection: close\r\nUpgrade-Insecure-Requests: 1\r\nX-Forwarded-For: 167.71.70.165\r\nConnection: Keep-Alive\r\n\r\n#015
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip-cef')
        self.assertEqual(response.rule_id, '65295')
        self.assertEqual(response.rule_level, 13)


    def test_bigip_asm_violation_detected_1(self) -> None:
        log = r'''
<134>Sep 19 13:35:00 bigip-4.pme-ds.f5.com ASM:CEF:0|F5|ASM|11.3.0|Successful Request|Successful Request|2| dvchost=bigip-4.pme-ds.f5.com dvc=172.16.73.34 cs1=topaz4-web4 cs1Label=policy_name cs2=/Common/topaz4-web4 cs2Label=http_class_name deviceCustomDate1=Sep 19 2012 11:38:36 deviceCustomDate1Label=policy_apply_date externalId=18205860747014045699 act=passed cn1=200 cn1Label=response_code src=10.4.1.101 spt=52963 dst=10.4.1.200 dpt=80 requestMethod=GET app=HTTP cs5=N/A cs5Label=x_forwarded_for_header_value rt=Sep 19 2012 13:35:00 deviceExternalId=0 cs4=N/A cs4Label=attack_type cs6=N/A cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4=N/A c6a4Label=ip_address_intelligence msg=N/A suid=2e769a9e1ea8b777 suser=N/A request=/ cs3Label=full_request cs3=GET / HTTP/1.0\r\nUser-Agent: Wget/1.12 (linux-gnu)\r\nAccept: */*\r\nHost: 10.4.1.200\r\nConnection: Keep-Alive\r\n\r\n
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip-cef')
        self.assertEqual(response.rule_id, '65296')
        self.assertEqual(response.rule_level, 12)


    def test_bigip_asm_violation_detected_2(self) -> None:
        log = r'''
<131>Sep 19 13:53:34 bigip-4.pme-ds.f5.com ASM:CEF:0|F5|ASM|11.3.0|200021069|Automated client access "wget"|5|dvchost=bigip-4.pme-ds.f5.com dvc=172.16.73.34 cs1=topaz4-web4 cs1Label=policy_name cs2=/Common/topaz4-web4 cs2Label=http_class_name deviceCustomDate1=Sep 19 2012 13:49:25 deviceCustomDate1Label=policy_apply_date externalId=18205860747014045723 act=blocked cn1=0 cn1Label=response_code src=10.4.1.101 spt=52975 dst=10.4.1.200 dpt=80 requestMethod=GET app=HTTP cs5=N/A cs5Label=x_forwarded_for_header_value rt=Sep 19 2012 13:53:33 deviceExternalId=0 cs4=Non-browser Client cs4Label=attack_type cs6=N/A cs6Label=geo_location c6a1= c6a1Label=device_address c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4=N/A c6a4Label=ip_address_intelligence msg=N/A suid=86c4f8bf7349cac9 suser=N/A request=/ cs3Label=full_request cs3=GET / HTTP/1.0\r\nUser-Agent: Wget/1.12 (linux-gnu)\r\nAccept: */*\r\nHost: 10.4.1.200\r\nConnection: Keep-Alive\r\n\r\n
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip-cef')
        self.assertEqual(response.rule_id, '65296')
        self.assertEqual(response.rule_level, 12)


    def test_bigip_asm_anomaly_detected_1(self) -> None:
        log = r'''
<131>Sep 19 13:53:34 bigip-4.pme-ds.f5.com ASM:CEF:0|F5|componentName|componentName|componentName|componentName|40| dvchost=componentName dvc=componentName cs1=componentName cs1Label=policy_name cs2=componentName cs2Label=web_application_name deviceCustomDate1=componentName deviceCustomDate1Label=policy_apply_date act=componentName cn3=%llu cn3Label=attack_id cs4=componentName cs4Label=attack_status request=componentName src=componentName cs6=componentName cs6Label=geo_location cs5=componentName cs5Label=detection_mode rt=componentName cn1=40 cn1Label=detection_average cn2=%llu cn2Label=dropped_requests
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip-cef')
        self.assertEqual(response.rule_id, '65297')
        self.assertEqual(response.rule_level, 12)


    def test_bigip_asm_anomaly_detected_2(self) -> None:
        log = r'''
<131>Sep 19 13:53:34 bigip-4.pme-ds.f5.com ASM:CEF:0|F5|componentName|componentName|componentName|componentName|40| dvchost=componentName dvc=componentName cs1=componentName cs1Label=policy_name cs2=componentName cs2Label=web_application_name deviceCustomDate1=componentName deviceCustomDate1Label=policy_apply_date act=componentName cn3=%llu cn3Label=attack_id cs4=componentName cs4Label=attack_status src=componentName cs6=componentName cs6Label=geo_location cn2=%llu cn2Label=dropped_requests rt=componentName
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip-cef')
        self.assertEqual(response.rule_id, '65297')
        self.assertEqual(response.rule_level, 12)


    def test_bigip_asm_anomaly_detected_3(self) -> None:
        log = r'''
<131>Sep 19 13:53:34 bigip-4.pme-ds.f5.com ASM:CEF:0|F5|componentName|componentName|componentName|componentName|40| dvchost=componentName dvc=componentName cs1=componentName cs1Label=policy_name cs2=componentName cs2Label=web_application_name deviceCustomDate1=componentName deviceCustomDate1Label=policy_apply_date act=componentName cn3=%llu cn3Label=attack_id cs4=componentName cs4Label=attack_status src=componentName cs6=componentName cs6Label=geo_location rt=componentName cn2=%llu cn2Label=dropped_requests cn4=%u cn4Label=violation_counter
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip-cef')
        self.assertEqual(response.rule_id, '65297')
        self.assertEqual(response.rule_level, 12)


    def test_f5_bigip_info_message_detected(self) -> None:
        log = r'''
May  5 04:26:19 hostname info process[20175]: 01011111:0: MCP Connection %s, exiting
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65298')
        self.assertEqual(response.rule_level, 2)


    def test_f5_bigip_notice_message_detected(self) -> None:
        log = r'''
May  5 04:26:19 hostname notice process[20175]: 01011111:0: MCP Connection %s, exiting
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65299')
        self.assertEqual(response.rule_level, 2)


    def test_f5_bigip_warning_message_detected(self) -> None:
        log = r'''
May  5 04:26:19 hostname warning process[20175]: 01011111:0: MCP Connection %s, exiting
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65300')
        self.assertEqual(response.rule_level, 2)


    def test_f5_bigip_alert_message_detected(self) -> None:
        log = r'''
May  5 04:26:19 hostname alert process[20175]: 01011111:0: MCP Connection %s, exiting
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65301')
        self.assertEqual(response.rule_level, 4)


    def test_f5_bigip_critical_message_detected(self) -> None:
        log = r'''
May  5 04:26:19 hostname crit process[20175]: 01011111:0: MCP Connection %s, exiting
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'f5-bigip')
        self.assertEqual(response.rule_id, '65302')
        self.assertEqual(response.rule_level, 7)

