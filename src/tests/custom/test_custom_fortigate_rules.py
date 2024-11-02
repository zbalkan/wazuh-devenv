#!/usr/bin/python3
# -*- coding: utf-8 -*-

from internal.logtest import LogtestStatus, send_log


def test_basic_log() -> None:
    log = 'date=2019-10-10 time=17:01:31 devname="FG111E-INFT2"'
    response = send_log(log)

    # Test the response

    # Ensure there is a rule match
    assert response.status == LogtestStatus.RuleMatch

    # Ensure there is a decoder matching
    assert response.decoder == 'fortigate-custom'

    # Ensure the rule information is descriptive
    assert response.rule_description == 'Fortigate messages grouped.'

    # Use an available rule ID
    assert response.rule_id == '222000'

    # Ensure the rule level is correct
    assert response.rule_level == 3

    # Ensure the parsed data is correct
    assert response.get_data_field(['date']) == '2019-10-10'
    assert response.get_data_field(['time']) == '17:01:31'
    assert response.get_data_field(['devname']) == 'FG111E-INFT2'

    # Ensure the rule groups are correct
    assert 'custom' in response.rule_groups
    assert 'fortigate' in response.rule_groups


def test_firewall_log() -> None:
    log = 'date=2019-10-10 time=17:01:31 devname="FG111E-INFT2" devid="FG201E4Q17901611" logid="0000000020" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1573570891 srcip=192.168.56.105 srcname="wazuh.test.local" srcport=63874 srcintf="port1" srcintfrole="lan" dstip=54.97.146.111 dstport=443 dstintf="wan1" dstintfrole="wan" poluuid="3e421d8c-0210-51ea-2e5e-6dd151c37590" sessionid=261713795 proto=6 action="accept" user="WAZUH" authserver="FSSO_TEST_LOCAL" policyid=131 policytype="policy" service="HTTPS" dstcountry="United Kingdom" srccountry="Reserved" trandisp="snat" transip=195.46.111.2 transport=63874 appid=45553 app="Microsoft.Outlook.Office.365" appcat="Email" apprisk="medium" applist="INF-APP-MONITOR" appact="detected" duration=815 sentbyte=13941 rcvdbyte=13429 sentpkt=58 rcvdpkt=63 sentdelta=360 rcvddelta=2189 devtype="Windows PC" devcategory="Windows Device" osname="Windows" osversion="8.1" mastersrcmac="fc:45:96:44:79:c9" srcmac="fc:45:96:44:79:c9" srcserver=1 dstdevtype="Router/NAT Device" dstdevcategory="None" masterdstmac="28:8b:1c:db:7c:48" dstmac="28:8b:1c:db:7c:48" dstserver=0'
    response = send_log(log)

    # Test the response

    # Ensure there is a rule match
    assert response.status == LogtestStatus.RuleMatch

    # Ensure there is a decoder matching
    assert response.decoder == 'fortigate-firewall-v5'

    # Ensure the rule information is descriptive
    assert response.rule_description == 'Fortigate: Traffic to be aware of.'

    # Use an available rule ID
    assert response.rule_id == '81618'

    # Ensure the rule level is correct
    assert response.rule_level == 1

    # Ensure the parsed data is correct
    assert response.get_data_field(['app']) == 'Microsoft.Outlook.Office.365'
    assert response.get_data_field(['action']) == 'accept'
    assert response.get_data_field(['dstuser']) == 'WAZUH'

    # Ensure the rule groups are correct
    assert 'syslog' in response.rule_groups
    assert 'fortigate' in response.rule_groups
