#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from fortigate.ini
class TestFortigateRules(unittest.TestCase):

    def test_fortigate_ipsec_dpd_failed(self) -> None:
        log = '''date=2016-06-15 time=10:42:31 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=event subtype=vpn level=error vd="root" logdesc="IPsec DPD failed" msg="IPsec DPD failure" action=dpd remip=1.2.3.4 locip=4.3.2.1 remport=500 locport=500 outintf="wan1" cookies="fsdagfdfgfdgfdg/qwerweafasfefsd" user="N/A" group="N/A" xauthuser="N/A" xauthgroup="N/A" assignip=N/A vpntunnel="BW" status=dpd_failure'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81604')
        self.assertEqual(response.rule_level, 4)


    def test_fortigate_login_failed_1(self) -> None:
        log = '''date=2016-06-14 time=12:22:01 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=event subtype=system level=alert vd="root" logdesc="Admin login failed" sn=0 user="gfedhf" ui=https(4.3.5.253) action=login status=failed reason="name_invalid" msg="Administrator gfedhf login failed from https(4.3.5.253) because of invalid user name"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81606')
        self.assertEqual(response.rule_level, 4)


    def test_fortigate_login_failed_2(self) -> None:
        log = '''date=2016-06-17 time=02:37:41 devname=Mobipay_Firewall devid=FGTXXXX9999999999 logid=0100032002 type=event subtype=system level=alert vd="root" logdesc="Admin login failed" sn=0 user="root" ui=ssh(222.186.130.227) action=login status=failed reason="name_invalid" msg="Administrator root login failed from ssh(222.186.130.227) because of invalid user name"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81606')
        self.assertEqual(response.rule_level, 4)


    def test_fortigate_configuration_changed(self) -> None:
        log = '''date=2016-06-14 time=10:47:23 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=event subtype=system level=alert vd="root" logdesc="Configuration changed" user="admin" ui=https(105.232.255.15) msg="Configuration is changed in the admin session"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81608')
        self.assertEqual(response.rule_level, 7)


    def test_fortigate_default_tunneling_setting_could_be_ips(self) -> None:
        log = '''date=2016-06-15 time=09:41:35 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=utm subtype=ips eventtype=signature level=alert vd="root" severity=info srcip=192.168.10.8 dstip=157.55.235.162 srcintf="internal2" dstintf="wan2" policyid=2 sessionid=1473454 action=reset proto=6 service=tcp/20480 attack="HTTP.Unknown.Tunnelling" srcport=62216 dstport=80 direction=outgoing attackid=107347981 profile="default" ref="http://www.fortinet.com/ids/VID107347981" incidentserialno=1999871775 msg="http_decoder: HTTP.Unknown.Tunnelling,"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81610')
        self.assertEqual(response.rule_level, 4)


    def test_fortigate_firewall_configuration_changes_1(self) -> None:
        log = '''date=2016-06-16 time=09:03:03 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=event subtype=system level=information vd="root" logdesc="Object attribute configured" user="admin" ui="GUI(4.3.5.8)" action=Edit cfgtid=2162752 cfgpath="firewall.service.custom" cfgobj="Custom-TCP_10443" cfgattr="tcp-portrange[->10443]udp-portrange[->]sctp-portrange[->]" msg="Edit firewall.service.custom Custom-TCP_10443"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81612')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_firewall_configuration_changes_2(self) -> None:
        log = '''date=2016-06-16 time=09:03:03 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=event subtype=system level=information vd="root" logdesc="Object attribute configured" user="admin" ui="GUI(4.3.5.8)" action=Edit cfgtid=2162751 cfgpath="firewall.service.custom" cfgobj="Custom-TCP_10443" cfgattr="protocol[TCP/UDP/SCTP->TCP/UDP/SCTP]udp-portrange[->]sctp-portrange[->]" msg="Edit firewall.service.custom Custom-TCP_10443"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81612')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_firewall_configuration_changes_3(self) -> None:
        log = '''date=2016-06-16 time=08:41:14 devname=Mobipay_Firewall devid=FGTXXXX9999999999 logid=0100044546 type=event subtype=system level=information vd="root" logdesc="Attribute configured" user="a@b.com.na" ui="GUI(10.42.8.253)" action=Edit cfgtid=2162733 cfgpath="log.threat-weight" cfgattr="failed-connection[low->medium]" msg="Edit log.threat-weight "'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81612')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_ssl_vpn_user_failed_login_attempt(self) -> None:
        log = '''date=2016-06-15 time=21:35:09 devname=Device_Name devid=FGTXXXX9999999999 logid=0101039426 type=event subtype=vpn level=alert vd="root" logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" tunnelid=0 remip=2.4.6.8 tunnelip=(null) user="my_user_name" group="N/A" dst_host="N/A" reason="sslvpn_login_unknown_user" msg="SSL user failed to logged in"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81614')
        self.assertEqual(response.rule_level, 4)


    def test_fortigate_user_logout_successful(self) -> None:
        log = '''date=2016-06-16 time=08:48:28 devname=Device_Name devid=FGTXXXX9999999999 logid=0100032003 type=event subtype=system level=information vd="root" logdesc="Admin logout successful" sn=1466062693 user="a@b.com.na" ui=https(4.3.5.253) action=logout status=success duration=615 state="Config-Changed" reason=exit msg="Administrator a@b.com.na logged out from https(2.3.8.1)"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81616')
        self.assertEqual(response.rule_level, 4)


    def test_fortigate_3_traffic_to_be_aware_of_1(self) -> None:
        log = '''Dec 23 11:13:03 date=2011-07-24 time=10: 13:03 devname=Device_Name device_id=FGTXXXX9999999999 log_id=0038016004 type=traffic subtype=other pri=notice vd=root SN=9999999999 duration=0 user=N/A group=N/A rule=0 policyid=0 proto=6 service=tcp app_type=N/A status=deny src=10.3.3.3 srcname=10.3.3.3 dst=10.4.4.4 dstname=10.4.4.4 src_int=N/A dst_int="N/A" sent=0 rcvd=0'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v3')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_3_traffic_to_be_aware_of_2(self) -> None:
        log = '''Mar 24 12:19:43 date=2011-07-25 time=08: 19:42 devname=Name_of_Device device_id=FGXXXX9999999999 log_id=0038016002 type=traffic subtype=other pri=notice vd=root SN=9999999999 duration=0 user=N/A group=N/A rule=0 policyid=0 proto=1 service=3/icmp app_type=N/A status=accept src=10.1.1.1 srcname=10.1.1.1 dst=10.2.2.2 dstname=10.2.2.2 src_int=N/A dst_int="N/A" sent=0 rcvd=0 sent_pkt=0 rcvd_pkt=0 src_port=0 dst_port=0 vpn="N/A" tran_ip=0.0.0.0 tran_port=0 dir_disp=org tran_disp=noop'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v3')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_4_traffic_to_be_aware_of_1(self) -> None:
        log = '''Feb 20 12:26:25 date=2011-02-20 time=12: 26:24 devname=Device_Name device_id=FGXXXX0000000001 log_id=9999999999 type=traffic subtype=other pri=notice status=deny vd="root" src=10.10.10.10 srcname=10.10.10.10 src_port=1111 dst=10.20.30.40 dstname=10.20.30.40 dst_port=2222 service=65535/tcp proto=6 app_type=N/A duration=0 rule=0 policyid=0 identidx=0 sent=0 rcvd=0 shaper_drop_sent=0 shaper_drop_rcvd=0 perip_drop=0 shaper_sent_name="N/A" shaper_rcvd_name="N/A" perip_name="N/A" vpn="N/A" src_int="Interface Name" dst_int="internal" SN=123456 app="N/A" app_cat="N/A" user="N/A" group="N/A" carrier_ep="N/A"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v4')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_4_traffic_to_be_aware_of_2(self) -> None:
        log = '''Feb 19 22:00:07 date=2011-02-19 time=22: 00:07 devname=Device_Name device_id=FGXXXX1231231231 log_id=3213213213 type=traffic subtype=other pri=notice status=deny vd="root" src=10.10.10.1 srcname=10.10.10.1 src_port=1111 dst=10.9.8.7 dstname=10.9.8.7 dst_port=2222 service=65535/udp proto=17 app_type=N/A duration=0 rule=0 policyid=0 identidx=0 sent=0 rcvd=0 shaper_drop_sent=0 shaper_drop_rcvd=0 perip_drop=0 shaper_sent_name="N/A" shaper_rcvd_name="N/A" perip_name="N/A" vpn="N/A" src_int="wan1" dst_int="root" SN=333333 app="N/A" app_cat="N/A" user="N/A" group="N/A" carrier_ep="N/A"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v4')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_4_traffic_to_be_aware_of_3(self) -> None:
        log = '''Feb 20 12:31:11 date=2011-02-20 time=12: 31:09 devname=Name_of_Device device_id=FGXXXX1000000000 log_id=8888888888 type=traffic subtype=other pri=notice status=accept vd="root" src=192.168.0.1 srcname=192.168.0.1 src_port=0 dst=192.168.254.254 dstname=192.168.254.254 dst_port=0 service=11/icmp proto=1 app_type=N/A duration=0 rule=0 policyid=0 identidx=0 sent=0 rcvd=0 shaper_drop_sent=0 shaper_drop_rcvd=0 shaper_sent_name="N/A" shaper_rcvd_name="N/A" perip_name="N/A" vpn="N/A" src_int="root" dst_int="N/A" SN=123412341234 app="N/A" app_cat="N/A" user="N/A" group="N/A" carrier_ep="N/A"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v4')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_5_traffic_to_be_aware_of_1(self) -> None:
        log = '''date=2016-06-16 time=10:19:23 devname=Device_Name devid=FGTXXXX9999999999 logid=0000000013 type=traffic subtype=forward level=notice vd=root srcip=7.3.8.5 srcport=57727 srcintf="internal1" dstip=7.8.9.81 dstport=80 dstintf="wan1" poluuid=d6217c58-8c42-51e5-c3a6-c7766895cbfd sessionid=181876 proto=6 action=deny policyid=8 dstcountry="Reserved" srccountry="Reserved" trandisp=snat transip=160.242.8.82 transport=57727 service="HTTP" appid=107347980 app="Proxy.HTTP" appcat="Proxy" apprisk=critical applist="default" appact=drop-session duration=30 sentbyte=0 rcvdbyte=3042 sentpkt=0 utmaction=block countapp=1 crscore=10 craction=1048576'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_5_traffic_to_be_aware_of_2(self) -> None:
        log = '''date=2016-06-16 time=10:49:08 devname=Device_Name devid=FGTXXXX9999999999 logid=0000000013 type=traffic subtype=forward level=notice vd=root srcip=4.3.5.161 srcport=51082 srcintf="internal1" dstip=54.192.197.185 dstport=80 dstintf="wan1" poluuid=d6217c58-8c42-51e5-c3a6-c7766895cbfd sessionid=199618 proto=6 action=deny policyid=8 dstcountry="United States" srccountry="Reserved" trandisp=snat transip=160.242.8.82 transport=51082 service="HTTP" appid=6 app="BitTorrent" appcat="P2P" apprisk=high applist="default" appact=drop-session duration=3 sentbyte=60 rcvdbyte=3050 sentpkt=1 utmaction=block countapp=1 crscore=5 craction=1048576'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_6_traffic_to_be_aware_of_1(self) -> None:
        log = '''date=2019-05-13 time=11:45:04 logid="0000000013" type="traffic" subtype="forward" level="notice" vd="vdom1" eventtime=1557773104815101919 srcip=10.1.100.11 srcport=60446 srcintf="port12" srcintfrole="undefined" dstip=172.16.200.55 dstport=80 dstintf="port11" dstintfrole="undefined" srcuuid="48420c8a-5c88-51e9-0424-a37f9e74621e" dstuuid="187d6f46-5c86-51e9-70a0-fadcfc349c3e" poluuid="3888b41a-5c88-51e9-cb32-1c32c66b4edf" sessionid=359260 proto=6 action="close" policyid=4 policytype="policy" service="HTTP" dstcountry="Reserved" srccountry="Reserved" trandisp="snat" transip=172.16.200.2 transport=60446 appid=15893 app="HTTP.BROWSER" appcat="Web.Client" apprisk="medium" applist="g-default" duration=1 sentbyte=412 rcvdbyte=2286 sentpkt=6 rcvdpkt=6 wanin=313 wanout=92 lanin=92 lanout=92 utmaction="block" countav=1 countapp=1 crscore=50 craction=2 osname="Ubuntu" mastersrcmac="a2:e9:00:ec:40:01" srcmac="a2:e9:00:ec:40:01" srcserver=0 utmref=65497-770'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_6_traffic_to_be_aware_of_2(self) -> None:
        log = '''date=2019-05-15 time=15:08:49 logid="0000000013" type="traffic" subtype="forward" level="notice" vd="vdom1" eventtime=1557958129950003945 srcip=10.1.100.22 srcport=50002 srcintf="port12" srcintfrole="undefined" dstip=172.16.100.100 dstport=53 dstintf="port11" dstintfrole="undefined" srcuuid="ae28f494-5735-51e9-f247-d1d2ce663f4b" dstuuid="ae28f494-5735-51e9-f247-d1d2ce663f4b" poluuid="ccb269e0-5735-51e9-a218-a397dd08b7eb" sessionid=6887 proto=17 action="accept" policyid=1 policytype="policy" service="DNS" dstcountry="Reserved" srccountry="Reserved" trandisp="snat" transip=172.16.200.2 transport=50002 duration=180 sentbyte=67 rcvdbyte=207 sentpkt=1 rcvdpkt=1 appcat="unscanned" utmaction="allow" countdns=1 osname="Linux" mastersrcmac="a2:e9:00:ec:40:41" srcmac="a2:e9:00:ec:40:41" srcserver=0 utmref=65495-306'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_6_traffic_to_be_aware_of_3(self) -> None:
        log = '''date=2019-05-15 time=18:03:41 logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1557968619 srcip=10.1.100.22 srcport=50798 srcintf="port10" srcintfrole="lan" dstip=195.8.215.136 dstport=443 dstintf="port9" dstintfrole="wan" poluuid="d8ce7a90-7763-51e9-e2be-741294c96f31" sessionid=4414 proto=6 action="client-rst" policyid=1 policytype="policy" service="HTTPS" dstcountry="France" srccountry="Reserved" trandisp="snat" transip=172.16.200.10 transport=50798 appid=16072 app="Dailymotion" appcat="Video/Audio" apprisk="elevated" applist="block-social.media" appact="drop-session" duration=5 sentbyte=1150 rcvdbyte=7039 sentpkt=13 utmaction="block" countapp=3 devtype="Unknown" devcategory="None" mastersrcmac="00:0c:29:51:38:5e" srcmac="00:0c:29:51:38:5e" srcserver=0 utmref=0-330'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81618')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_vpn_user_connected(self) -> None:
        log = '''date=2016-06-16 time=08:47:00 devname=Device_Name devid=FGTXXXX9999999999 logid=0101039947 type=event subtype=vpn level=information vd="root" logdesc="SSL VPN tunnel up" action="tunnel-up" tunneltype="ssl-tunnel" tunnelid=1050355638 remip=9.8.7.7 tunnelip=1.2.4.6 user="my_user_name" group="SSL_VPN" dst_host="N/A" reason="N/A" msg="SSL tunnel established"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81622')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_vpn_user_disconnected(self) -> None:
        log = '''date=2016-06-16 time=08:49:26 devname=Device_Name devid=FGTXXXX9999999999 logid=0101039948 type=event subtype=vpn level=information vd="root" logdesc="SSL VPN tunnel down" action="tunnel-down" tunneltype="ssl-tunnel" tunnelid=1050355638 remip=5.7.8.9 tunnelip=8.4.2.1 user="my_user_name" group="SSL_VPN" dst_host="N/A" reason="N/A" duration=147 sentbyte=2284 rcvdbyte=2630 msg="SSL tunnel shutdown"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81624')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_user_successfully_logged_into_firewall_interface(self) -> None:
        log = '''date=2016-06-16 time=16:22:34 devname=Mobipay_Firewall devid=FGTXXXX9999999999 logid=0100032001 type=event subtype=system level=information vd="root" logdesc="Admin login successful" sn=1466090554 user="a@b.com.na" ui=https(10.42.8.253) action=login status=success reason=none profile="super_admin" msg="Administrator a@b.com.na logged in successfully from https(10.42.8.253)"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81626')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_attack_detected(self) -> None:
        log = '''Mar 22 19:21:00 10.10.10.10 date=2016-03-22 time=19:20:46 devname=Text devid=FGT3HD0000000000 logid=0000018000 type=anomaly subtype=anomaly level=alert vd="root" severity=critical srcip=10.10.10.35 dstip=10.10.10.84 srcintf="port2" sessionid=0 action=detected proto=6 service=tcp/36875 count=1903 attack="tcp_syn_flood" srcport=32835 dstport=2960 attackid=100663396 profile="DoS-policy1" ref="http://www.fortinet.com/ids/VID100663396" msg="anomaly: tcp_syn_flood, 2001 > threshold 2000, repeats 1903 times" crscore=50 crlevel=critical'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81628')
        self.assertEqual(response.rule_level, 11)


    def test_fortigate_5_attack_dropped(self) -> None:
        log = '''Mar 22 19:21:00 10.10.10.10 date=2016-03-22 time=19:20:46 devname=Text devid=FGT3HD0000000000 logid=0000018000 type=anomaly subtype=anomaly level=alert vd="root" severity=critical srcip=10.10.10.61 dstip=10.10.10.84 srcintf="port2" sessionid=0 action=dropped proto=6 service=NONE count=9 attack="IP.Bad.Header" attackid=127 profile="N/A" ref="http://www.fortinet.com/ids/VID127" msg="anomaly: IP.Bad.Header, repeats 9 times" crscore=50 crlevel=critical'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81629')
        self.assertEqual(response.rule_level, 6)


    def test_fortigate_6_attack_dropped(self) -> None:
        log = '''date=2019-05-15 time=17:56:41 logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" eventtime=1557968201 severity="critical" srcip=10.1.100.22 srccountry="Reserved" dstip=172.16.200.55 srcintf="port10" srcintfrole="lan" dstintf="port9" dstintfrole="wan" sessionid=4017 action="dropped" proto=6 service="HTTP" policyid=1 attack="Adobe.Flash.newfunction.Handling.Code.Execution" srcport=46810 dstport=80 hostname="172.16.200.55" url="/ips/sig1.pdf" direction="incoming" attackid=23305 profile="block-critical-ips" ref="http://www.fortinet.com/ids/VID23305" incidentserialno=582633933 msg="applications3: Adobe.Flash.newfunction.Handling.Code.Execution," crscore=50 craction=4096 crlevel="critical"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81629')
        self.assertEqual(response.rule_level, 6)


    def test_fortigate_attack_session_cleared(self) -> None:
        log = '''date=2019-05-13 time=17:05:59 logid="0720018433" type="utm" subtype="anomaly" eventtype="anomaly" level="alert" vd="vdom1" eventtime=1557792359461869329 severity="critical" srcip=10.1.100.11 srccountry="Reserved" dstip=172.16.200.55 srcintf="port12" srcintfrole="undefined" sessionid=0 action="clear_session" proto=1 service="PING" count=1 attack="icmp_flood" icmpid="0x1474" icmptype="0x08" icmpcode="0x00" attackid=16777316 policyid=1 policytype="DoS-policy" ref="http://www.fortinet.com/ids/VID16777316" msg="anomaly: icmp_flood, 51 > threshold 50" crscore=50 craction=4096 crlevel="critical"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81630')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_firewall_configuration_changes(self) -> None:
        log = '''date=2016-06-16 time=09:03:03 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=event subtype=system level=information vd="root" logdesc="Object attribute configured" user="admin" ui="GUI(4.3.5.8)" action=Add cfgtid=2162750 cfgpath="firewall.service.custom" cfgobj="Custom-TCP_10443" cfgattr="" msg="Add firewall.service.custom Custom-TCP_10443"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81631')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_5_app_passed_by_firewall(self) -> None:
        log = '''2018 Apr 09 16:03:37 inwazuhmgr->172.24.0.253 date=2018-04-09 time=16:03:37 devname=BA-RSYS-FW devid=FG600C3912803212 logid="1059028704" type="utm" subtype="app-ctrl" eventtype="app-ctrl-all" level="information" vd="BA-EXORA" logtime=1523270017 appid=16009 srcip=172.24.42.175 dstip=111.221.29.254 srcport=55139 dstport=443 srcintf="port3" srcintfrole="wan" dstintf="port5" dstintfrole="undefined" proto=6 service="HTTPS" policyid=107 sessionid=3454887534 applist="block-high-risk" appcat="Update" app="MS.Windows.Update" action="pass" hostname="*.vortex-win.data.microsoft.com" incidentserialno=1405558813 url="/" msg="Update: MS.Windows.Update," apprisk="elevated" scertcname="*.vortex-win.data.microsoft.com"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81633')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_6_app_passed_by_firewall(self) -> None:
        log = '''date=2019-05-15 time=18:03:36 logid="1059028704" type="utm" subtype="app-ctrl" eventtype="app-ctrl-all" level="information" vd="root" eventtime=1557968615 appid=40568 srcip=10.1.100.22 dstip=195.8.215.136 srcport=50798 dstport=443 srcintf="port10" srcintfrole="lan" dstintf="port9" dstintfrole="wan" proto=6 service="HTTPS" direction="outgoing" policyid=1 sessionid=4414 applist="block-social.media" appcat="Web.Client" app="HTTPS.BROWSER" action="pass" hostname="www.dailymotion.com" incidentserialno=1962906680 url="/" msg="Web.Client: HTTPS.BROWSER," apprisk="medium" scertcname="*.dailymotion.com" scertissuer="DigiCert SHA2 High Assurance Server CA"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81633')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_app_blocked_by_firewall(self) -> None:
        log = '''date=2019-05-15 time=18:03:35 logid="1059028705" type="utm" subtype="app-ctrl" eventtype="app-ctrl-all" level="warning" vd="root" eventtime=1557968615 appid=16072 srcip=10.1.100.22 dstip=195.8.215.136 srcport=50798 dstport=443 srcintf="port10" srcintfrole="lan" dstintf="port9" dstintfrole="wan" proto=6 service="HTTPS" direction="incoming" policyid=1 sessionid=4414 applist="block-social.media" appcat="Video/Audio" app="Dailymotion" action="block" hostname="www.dailymotion.com" incidentserialno=1962906682 url="/" msg="Video/Audio: Dailymotion," apprisk="elevated"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81634')
        self.assertEqual(response.rule_level, 5)


    def test_fortigate_vpn_related_information(self) -> None:
        log = '''2018 Apr 09 16:03:11 inwazuhmgr->172.0.0.1 date=2018-04-09 time=16:03:11 devname=BA-BE-BI devid=FG600C1234567890 logid="0101037141" type="event" subtype="vpn" level="notice" vd="BA-BEBI" logtime=1523269991 logdesc="IPsec tunnel statistics" msg="IPsec tunnel statistics" action="tunnel-stats" remip=1.1.1.1 locip=1.1.1.1 remport=500 locport=500 outintf="port3" cookies="c95409asssss4d44/b8a16eeeeebe269a" user="N/A" group="N/A" xauthuser="N/A" xauthgroup="N/A" assignip=N/A vpntunnel="AWS-VPN-B" tunnelip=N/A tunnelid=2490314698 tunneltype="ipsec" duration=243565 sentbyte=116502517 rcvdbyte=347903642 nextstat=600'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81636')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_5_blocked_url_because_a_virus_was_detected(self) -> None:
        log = '''date=2018-05-31 time=08:58:56 devname="BA-RSYS-FW" devid="FG600C3912803212" logid="0211008192" type="utm" subtype="virus" eventtype="infected" level="warning" vd="BA-EXORA" eventtime=1527737336 msg="File is infected." action="blocked" service="HTTP" sessionid=377413095 srcip=172.24.12.52 dstip=164.100.80.203 srcport=64982 dstport=80 srcintf="port5" srcintfrole="undefined" dstintf="port3" dstintfrole="wan" policyid=108 proto=6 direction="incoming" filename="FrontPageImgHandler.ashx" quarskip="File-was-not-quarantined." virus="Malware_Generic.P0" dtype="Virus" ref="http://www.fortinet.com/ve?vn=Malware_Generic.P0" virusid=7024603 url="http://www.karsec.gov.in/FrontPageImgHandler.ashx?id=12" profile="Web-Browsing" agent="Chrome/66.0.3359.181" analyticscksum="a9165dbae34e6e2952270536e95a2bb154dff0cfcdf41315f0796ee14b36123b" analyticssubmit="false" crscore=50 crlevel="critical"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81639')
        self.assertEqual(response.rule_level, 6)


    def test_fortigate_6_blocked_url_because_a_virus_was_detected(self) -> None:
        log = '''date=2019-05-13 time=11:45:03 logid="0211008192" type="utm" subtype="virus" eventtype="infected" level="warning" vd="vdom1" eventtime=1557773103767393505 msg="File is infected." action="blocked" service="HTTP" sessionid=359260 srcip=10.1.100.11 dstip=172.16.200.55 srcport=60446 dstport=80 srcintf="port12" srcintfrole="undefined" dstintf="port11" dstintfrole="undefined" policyid=4 proto=6 direction="incoming" filename="eicar.com" quarskip="File-was-not-quarantined." virus="EICAR_TEST_FILE" dtype="Virus" ref="http://www.fortinet.com/ve?vn=EICAR_TEST_FILE" virusid=2172 url="http://172.16.200.55/virus/eicar.com" profile="g-default" agent="curl/7.47.0" analyticscksum="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" analyticssubmit="false" crscore=50 craction=2 crlevel="critical"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81639')
        self.assertEqual(response.rule_level, 6)


    def test_fortigate_url_belongs_to_an_allowed_category(self) -> None:
        log = '''2018 Jun 21 00:00:35 XXX->127.0.0.1 date=2018-06-21 time=03:00:35 devname="xxx" devid="FG123341414414" logid="111111111" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" vd="xxx" eventtime=111111111 policyid=111 sessionid=111111111 srcip=127.0.0.1 srcport=11111 srcintf="port1" srcintfrole="undefined" dstip=127.0.0.1 dstport=111 dstintf="port111" dstintfrole="undefined" proto=1 service="XXX" hostname="xxxxx.com" profile="xx" action="passthrough" reqtype="direct" url="/xxxxxxxxxxxx" sentbyte=11 rcvdbyte=111 direction="outgoing" msg="URL belongs to an allowed category in policy" method="domain" cat=50 catdesc="Information and Computer Security"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81640')
        self.assertEqual(response.rule_level, 1)


    def test_fortigate_virtual_cluster_detected_member_join(self) -> None:
        log = '''date=2019-05-10 time=09:53:18 logid="0108037894" type="event" subtype="ha" level="critical" vd="root" eventtime=1557507199208575235 logdesc="Virtual cluster member joined" msg="Virtual cluster detected member join" vcluster=1 ha_group=0 sn="FG2K5E3916900286"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81642')
        self.assertEqual(response.rule_level, 3)


    def test_fortigate_ssl_fatal_alert(self) -> None:
        log = '''date=2019-05-10 time=15:48:31 logid="0105048038" type="event" subtype="wad" level="error" vd="root" eventtime=1557528511221374615 logdesc="SSL Fatal Alert received" session_id=5f88ddd1 policyid=0 srcip=172.18.70.15 srcport=59880 dstip=91.189.89.223 dstport=443 action="receive" alert="2" desc="unknown ca" msg="SSL Alert received"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81643')
        self.assertEqual(response.rule_level, 7)


    def test_fortigate_5_blocked_url_belongs_to_a_denied_category_in_policy_1(self) -> None:
        log = '''date=2016-06-15 time=11:44:46 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=utm subtype=webfilter eventtype=urlfilter level=warning vd="root" urlfilteridx=3 urlfilterlist="default" policyid=2 sessionid=1563645 user="" srcip=1.2.3.11 srcport=52414 srcintf="internal2" dstip=1.5.5.92 dstport=443 dstintf="wan2" proto=6 service=HTTPS hostname="4-edge-chat.facebook.com" profile="default" action=blocked reqtype=referral url="/p?partition=-2&cb=lz1k&failure=5&sticky_token=274&sticky_pool=atn2c06_chat-proxy" sentbyte=932 rcvdbyte=0 direction=outgoing msg="URL was blocked because it is in the URL filter list" crscore=30 crlevel=high'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81644')
        self.assertEqual(response.rule_level, 6)


    def test_fortigate_5_blocked_url_belongs_to_a_denied_category_in_policy_2(self) -> None:
        log = '''date=2016-06-15 time=23:57:11 devname=Device_Name devid=FGTXXXX9999999999 logid=9999999999 type=utm subtype=webfilter eventtype=urlfilter level=warning vd="root" urlfilteridx=3 urlfilterlist="default" policyid=8 sessionid=42895 user="" srcip=2.5.8.8 srcport=57629 srcintf="internal1" dstip=13.107.4.50 dstport=80 dstintf="wan1" proto=6 service=HTTP hostname="www.download.windowsupdate.com" profile="default" action=blocked reqtype=direct url="/msdownload/update/v3/static/trustedr/en/authrootstl.cab" sentbyte=217 rcvdbyte=0 direction=outgoing msg="URL was blocked because it is in the URL filter list" crscore=30 crlevel=high'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v5')
        self.assertEqual(response.rule_id, '81644')
        self.assertEqual(response.rule_level, 6)


    def test_fortigate_6_blocked_url_belongs_to_a_denied_category_in_policy(self) -> None:
        log = '''date=2019-05-13 time=16:29:45 logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="vdom1" eventtime=1557790184975119738 policyid=1 sessionid=381780 srcip=10.1.100.11 srcport=44258 srcintf="port12" srcintfrole="undefined" dstip=185.244.31.158 dstport=80 dstintf="port11" dstintfrole="undefined" proto=6 service="HTTP" hostname="morrishittu.ddns.net" profile="test-webfilter" action="blocked" reqtype="direct" url="/" sentbyte=84 rcvdbyte=0 direction="outgoing" msg="URL belongs to a denied category in policy" method="domain" cat=26 catdesc="Malicious Websites" crscore=30 craction=4194304 crlevel="high"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81644')
        self.assertEqual(response.rule_level, 6)


    def test_fortigate_ssl_anomalies_blocked_connection_1(self) -> None:
        log = '''date=2019-03-28 time=10:44:53 logid="1700062002" type="utm" subtype="ssl" eventtype="ssl-anomalies" level="warning" vd="vdom1" eventtime=1553795092 policyid=1 sessionid=10796 service="HTTPS" srcip=10.1.100.66 srcport=43602 dstip=104.154.89.105 dstport=443 srcintf="port2" srcintfrole="undefined" dstintf="port3" dstintfrole="undefined" proto=6 action="blocked" msg="Server certificate blocked" reason="block-cert-invalid"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81645')
        self.assertEqual(response.rule_level, 5)


    def test_fortigate_ssl_anomalies_blocked_connection_2(self) -> None:
        log = '''date=2019-03-28 time=10:51:17 logid="1700062002" type="utm" subtype="ssl" eventtype="ssl-anomalies" level="warning" vd="vdom1" eventtime=1553795476 policyid=1 sessionid=11110 service="HTTPS" srcip=10.1.100.66 srcport=49076 dstip=172.16.200.99 dstport=443 srcintf="port2" srcintfrole="undefined" dstintf="port3" dstintfrole="undefined" proto=6 action="blocked" msg="Server certificate blocked" reason="block-cert-untrusted"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81645')
        self.assertEqual(response.rule_level, 5)


    def test_fortigate_ssl_anomalies_blocked_connection_3(self) -> None:
        log = '''date=2019-03-28 time=10:55:43 logid="1700062002" type="utm" subtype="ssl" eventtype="ssl-anomalies" level="warning" vd="vdom1" eventtime=1553795742 policyid=1 sessionid=11334 service="HTTPS" srcip=10.1.100.66 srcport=49082 dstip=172.16.200.99 dstport=443 srcintf="port2" srcintfrole="undefined" dstintf="port3" dstintfrole="undefined" proto=6 action="blocked" msg="Server certificate blocked" reason="block-cert-req"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81645')
        self.assertEqual(response.rule_level, 5)


    def test_fortigate_ssl_anomalies_blocked_connection_4(self) -> None:
        log = '''date=2019-03-28 time=10:57:42 logid="1700062053" type="utm" subtype="ssl" eventtype="ssl-anomalies" level="warning" vd="vdom1" eventtime=1553795861 policyid=1 sessionid=11424 service="SMTPS" profile="block-unsupported-ssl" srcip=10.1.100.66 srcport=41296 dstip=172.16.200.99 dstport=8080 srcintf="port2" srcintfrole="undefined" dstintf=unknown-0 dstintfrole="undefined" proto=6 action="blocked" msg="Connection is blocked due to unsupported SSL traffic" reason="malformed input"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81645')
        self.assertEqual(response.rule_level, 5)


    def test_fortigate_ssl_anomalies_blocked_connection_5(self) -> None:
        log = '''date=2019-03-28 time=11:00:17 logid="1700062002" type="utm" subtype="ssl" eventtype="ssl-anomalies" level="warning" vd="vdom1" eventtime=1553796016 policyid=1 sessionid=11554 service="HTTPS" srcip=10.1.100.66 srcport=49088 dstip=172.16.200.99 dstport=443 srcintf="port2" srcintfrole="undefined" dstintf="port3" dstintfrole="undefined" proto=6 action="blocked" msg="Server certificate blocked" reason="block-cert-sni-mismatch"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81645')
        self.assertEqual(response.rule_level, 5)


    def test_fortigate_file_was_blocked_by_file_filter(self) -> None:
        log = '''date=2019-05-15 time=16:28:17 logid="1800063000" type="utm" subtype="cifs" eventtype="cifs-filefilter" level="warning" vd="vdom1" eventtime=1557962895 msg="File was blocked by file filter." direction="incoming" action="blocked" service="CIFS" srcip=10.1.100.11 dstip=172.16.200.44 srcport=56348 dstport=445 srcintf="port21" srcintfrole="undefined" dstintf="port23" dstintfrole="undefined" policyid=1 proto=16 profile="cifs" filesize="13824" filename="sample\\test.xls" filtername="1" filetype="msoffice"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'fortigate-firewall-v6')
        self.assertEqual(response.rule_id, '81646')
        self.assertEqual(response.rule_level, 5)

