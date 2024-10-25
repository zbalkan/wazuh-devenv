#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from cloudflare-waf.ini
class TestCloudflareWafRules(unittest.TestCase):

    def test_cloudflare_waf_get_method_event(self) -> None:
        log = r'''
{"ClientIP":"54.76.123.133","ClientRequestHost":"ae-preprod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/messages/actuator/health","EdgeEndTimestamp":"2021-07-27T21:26:42Z","EdgeResponseBytes":845,"EdgeResponseStatus":200,"EdgeStartTimestamp":"2021-07-27T21:26:42Z","RayID":"6758f291eb0b60df","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"99.83.222.19","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":200,"OriginResponseTime":20000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":1981,"CacheResponseStatus":200,"ClientCountry":"ie","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"unk"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92502')
        self.assertEqual(response.rule_level, 4)


    def test_cloudflare_waf_post_method_event(self) -> None:
        log = r'''
{"ClientIP":"52.17.243.194","ClientRequestHost":"ae-preprod.yap.com","ClientRequestMethod":"POST","ClientRequestURI":"/digi-ocr/detect/","EdgeEndTimestamp":"2021-07-27T21:26:38Z","EdgeResponseBytes":625,"EdgeResponseStatus":200,"EdgeStartTimestamp":"2021-07-27T21:26:38Z","RayID":"6758f27939a260c2","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"75.2.33.181","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":200,"OriginResponseTime":19000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":1678,"CacheResponseStatus":200,"ClientCountry":"ie","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"unk"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92503')
        self.assertEqual(response.rule_level, 5)


    def test_cloudflare_waf_put_method_event(self) -> None:
        log = r'''
{"ClientIP":"2001:8f8:1821:9fb3:1101:67f6:7f43:b124","ClientRequestHost":"ae-prod.yap.com","ClientRequestMethod":"PUT","ClientRequestURI":"/customers/api/stop-display","EdgeEndTimestamp":"2021-07-27T21:38:19Z","EdgeResponseBytes":997,"EdgeResponseStatus":200,"EdgeStartTimestamp":"2021-07-27T21:38:19Z","RayID":"675903985d4608ab","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"99.83.253.40","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":200,"OriginResponseTime":134000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":2050,"CacheResponseStatus":200,"ClientCountry":"ae","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"med"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92504')
        self.assertEqual(response.rule_level, 5)


    def test_cloudflare_waf_auth_event(self) -> None:
        log = r'''
{"ClientIP":"54.76.123.133","ClientRequestHost":"ae-prod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/auth/login","EdgeEndTimestamp":"2021-07-27T21:26:46Z","EdgeResponseBytes":2516,"EdgeResponseStatus":200,"EdgeStartTimestamp":"2021-07-27T21:26:46Z","RayID":"6758f2aaedc434cc","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"99.83.253.40","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":200,"OriginResponseTime":26000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":3223,"CacheResponseStatus":200,"ClientCountry":"ie","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"unk"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92506')
        self.assertEqual(response.rule_level, 4)


    def test_cloudflare_waf_auth_failure_event(self) -> None:
        log = r'''
{"ClientIP":"54.76.123.133","ClientRequestHost":"ae-prod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/auth/login","EdgeEndTimestamp":"2021-07-27T21:38:24Z","EdgeResponseBytes":2516,"EdgeResponseStatus":401,"EdgeStartTimestamp":"2021-07-27T21:38:24Z","RayID":"675903b56b1060b6","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"99.83.253.40","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":200,"OriginResponseTime":26000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":3224,"CacheResponseStatus":200,"ClientCountry":"ie","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"unk"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92507')
        self.assertEqual(response.rule_level, 7)


    def test_cloudflare_waf_returned_error_event(self) -> None:
        log = r'''
{"ClientIP":"54.76.123.133","ClientRequestHost":"ae-preprod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/messages/actuator/health","EdgeEndTimestamp":"2021-07-27T21:38:42Z","EdgeResponseBytes":845,"EdgeResponseStatus":409,"EdgeStartTimestamp":"2021-07-27T21:38:42Z","RayID":"67590425eaa434f5","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"99.83.222.19","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":200,"OriginResponseTime":18000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":1984,"CacheResponseStatus":200,"ClientCountry":"ie","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"unk"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92508')
        self.assertEqual(response.rule_level, 7)


    def test_cloudflare_waf_returned_400_code_event(self) -> None:
        log = r'''
{"ClientIP":"2.51.28.56","ClientRequestHost":"ae-prod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/cards/api/cards/debit/balance","EdgeEndTimestamp":"2021-07-27T22:25:07Z","EdgeResponseBytes":1001,"EdgeResponseStatus":400,"EdgeStartTimestamp":"2021-07-27T22:25:07Z","RayID":"67594824cf622c26","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"75.2.31.168","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":400,"OriginResponseTime":343000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":2115,"CacheResponseStatus":400,"ClientCountry":"ae","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"med"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92509')
        self.assertEqual(response.rule_level, 4)


    def test_cloudflare_waf_returned_401_code_event(self) -> None:
        log = r'''
{"ClientIP":"2402:8100:3913:f4c8:4150:2d5a:58b3:d6b","ClientRequestHost":"ae-prod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/customers/api/mobile-app-versions","EdgeEndTimestamp":"2021-07-27T04:57:43Z","EdgeResponseBytes":950,"EdgeResponseStatus":401,"EdgeStartTimestamp":"2021-07-27T04:57:42Z","RayID":"675349d64f193d60","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"75.2.31.168","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":401,"OriginResponseTime":905000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":2039,"CacheResponseStatus":401,"ClientCountry":"in","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"med"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92510')
        self.assertEqual(response.rule_level, 8)


    def test_cloudflare_waf_returned_403_code_event(self) -> None:
        log = r'''
{"ClientIP":"154.127.53.235","ClientRequestHost":"www.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/.env","EdgeEndTimestamp":"2021-07-27T09:49:02Z","EdgeResponseBytes":2111,"EdgeResponseStatus":403,"EdgeStartTimestamp":"2021-07-27T09:49:02Z","RayID":"6754f49cb94be04d","FirewallMatchesActions":["block"],"FirewallMatchesRuleIDs":["100016"],"FirewallMatchesSources":["waf"],"OriginIP":"","OriginSSLProtocol":"unknown","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"WAFAction":"drop","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"med","WAFRuleID":"100016","WAFRuleMessage":"Version Control - Information Disclosure","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":0,"CacheResponseStatus":0,"ClientCountry":"us","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"med"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92511')
        self.assertEqual(response.rule_level, 7)


    def test_cloudflare_waf_returned_404_code_event(self) -> None:
        log = r'''
{"ClientIP":"2a03:2880:ff:1c::face:b00c","ClientRequestHost":"www.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/wp-content/uploads/2018/04/02_FinalLogo_Yap-01-e1552502263276.png","EdgeEndTimestamp":"2021-07-27T09:51:56Z","EdgeResponseBytes":747,"EdgeResponseStatus":404,"EdgeStartTimestamp":"2021-07-27T09:51:55Z","RayID":"6754f8d649badbc8","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"99.83.253.40","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":404,"OriginResponseTime":480000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"miss","CacheTieredFill":false,"CacheResponseBytes":1973,"CacheResponseStatus":404,"ClientCountry":"us","ClientDeviceType":"desktop","ClientIPClass":"unknown","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"med"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92512')
        self.assertEqual(response.rule_level, 4)


    def test_cloudflare_waf_returned_405_code_event(self) -> None:
        log = r'''
{"ClientIP":"52.114.6.38","ClientRequestHost":"ae-preprod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/auth/oauth/oidc/token?client_id=jith@yopmail.com&client_secret=1212&grant_type=client_credentials","EdgeEndTimestamp":"2021-07-27T06:16:50Z","EdgeResponseBytes":833,"EdgeResponseStatus":405,"EdgeStartTimestamp":"2021-07-27T06:16:50Z","RayID":"6753bdc13cf51944","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"75.2.33.181","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":405,"OriginResponseTime":746000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":1973,"CacheResponseStatus":405,"ClientCountry":"hk","ClientDeviceType":"desktop","ClientIPClass":"unknown","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"med"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92513')
        self.assertEqual(response.rule_level, 4)


    def test_cloudflare_waf_returned_413_code_event(self) -> None:
        log = r'''
{"ClientIP":"2600:1f14:b62:9e04:9e4d:874f:5c00:d627","ClientRequestHost":"www.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/administrator/","EdgeEndTimestamp":"2021-07-27T20:53:26Z","EdgeResponseBytes":413,"EdgeResponseStatus":413,"EdgeStartTimestamp":"2021-07-27T20:53:26Z","RayID":"6758c1d5ab061392","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"","OriginSSLProtocol":"unknown","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":0,"OriginResponseTime":0,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":0,"CacheResponseStatus":0,"ClientCountry":"us","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"med"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92514')
        self.assertEqual(response.rule_level, 4)


    def test_cloudflare_waf_returned_500_code_event(self) -> None:
        log = r'''
{"ClientIP":"103.27.22.10","ClientRequestHost":"ae-preprod.yap.com","ClientRequestMethod":"GET","ClientRequestURI":"/customers/api/accounts","EdgeEndTimestamp":"2021-07-27T04:48:26Z","EdgeResponseBytes":1552,"EdgeResponseStatus":500,"EdgeStartTimestamp":"2021-07-27T04:48:25Z","RayID":"67533c3d9ed0d3f7","FirewallMatchesActions":[],"FirewallMatchesRuleIDs":[],"FirewallMatchesSources":[],"OriginIP":"75.2.33.181","OriginSSLProtocol":"TLSv1.2","OriginResponseBytes":0,"OriginResponseHTTPExpires":"","OriginResponseHTTPLastModified":"","OriginResponseStatus":500,"OriginResponseTime":1125000000,"WAFAction":"unknown","WAFFlags":"0","WAFMatchedVar":"","WAFProfile":"unknown","WAFRuleID":"","WAFRuleMessage":"","WorkerCPUTime":0,"WorkerStatus":"unknown","WorkerSubrequest":false,"WorkerSubrequestCount":0,"CacheCacheStatus":"unknown","CacheTieredFill":false,"CacheResponseBytes":2224,"CacheResponseStatus":500,"ClientCountry":"pk","ClientDeviceType":"desktop","ClientIPClass":"noRecord","ZoneID":276192118,"ZoneName":"yap.com","SecurityLevel":"unk"}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '92515')
        self.assertEqual(response.rule_level, 4)

