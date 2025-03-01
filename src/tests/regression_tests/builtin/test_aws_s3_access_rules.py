#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from aws_s3_access.ini
class TestAwsS3AccessRules(unittest.TestCase):

    def test_generic_s3(self) -> None:
        log = r'''
{"integration": "aws", "aws": {"log_info": {"aws_account_alias": "", "log_file": "access_logs/2021-04-29-09-49-06-51F541DE27C2AC50", "s3bucket": "wazuh-aws-wodle"}, "bucket_owner": "3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101", "bucket": "wazuh-cloudtrail", "time": "29/Apr/2021:08:47:53 +0000", "remote_ip": "92.57.74.50", "requester": "arn:aws:iam::166157441623:user/david.iglesias", "request_id": "T3BW07JM2HMSJH17", "operation": "REST.HEAD.BUCKET", "key": "-", "request_uri": "HEAD /wazuh-cloudtrail HTTP/1.1", "http_status": "200", "error_code": "-", "bytes_sent": "-", "object_sent": "-", "total_time": "29", "turn_around_time": "28", "referer": "-", "user_agent": "S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.991 Linux/4.9.230-0.1.ac.224.84.332.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.282-b08 java/1.8.0_282 vendor/Oracle_Corporation cfg/retry-mode/legacy", "version_id": "-", "host_id": "YnKG5o0K4Z3Lh0WD0QTJVXOBjiUwi1wcz2nnrCZa7BMu6xyX++sLbA43jEXTSRd2eoNwZty30g4=", "signature_version": "SigV4", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "authentication_type": "AuthHeader", "host_header": "s3.amazonaws.com", "tls_version": "TLSv1.2", "source": "s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80360')
        self.assertEqual(response.rule_level, 0)


    def test_aws_s3_delete_operation(self) -> None:
        log = r'''
{"integration":"aws","aws":{"log_info":{"aws_account_alias":"","log_file":"access_logs/2021-04-29-09-41-37-6CFDED3B1BCCDEB1","s3bucket":"wazuh-aws-wodle"},"bucket_owner":"3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101","bucket":"wazuh-cloudtrail","time":"29/Apr/2021:08:57:58 +0000","remote_ip":"213.194.148.169","requester":"arn:aws:iam::166157441623:user/carlos.ridao","request_id":"M5XS2MGJ6FEA5VTJ","operation":"REST.DELETE.BUCKETVERSIONS","key":"-","request_uri":"GET /?versions&max-keys=1&encoding-type=url HTTP/1.1","http_status":"200","error_code":"-","bytes_sent":"839","object_sent":"-","total_time":"54","turn_around_time":"53","referer":"-","user_agent":"S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.991 Linux/4.9.230-0.1.ac.224.84.332.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.282-b08 java/1.8.0_282 vendor/Oracle_Corporation cfg/retry-mode/legacy","version_id":"-","host_id":"JyPaquNlVOP38Ap/6E0zqnh5Zj75+9KAv0weFdQChcLd6oaNZZxWyJUPhQgahDu4EHWDy7zQOsA=","signature_version":"SigV4","cipher_suite":"ECDHE-RSA-AES128-GCM-SHA256","authentication_type":"AuthHeader","host_header":"wazuh-cloudtrail.s3.us-east-1.amazonaws.com","tls_version":"TLSv1.2","source":"s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80361')
        self.assertEqual(response.rule_level, 3)


    def test_operation_get(self) -> None:
        log = r'''
{"integration": "aws", "aws": {"log_info": {"aws_account_alias": "", "log_file": "access_logs/2021-04-29-09-41-37-6CFDED3B1BCCDEB1", "s3bucket": "wazuh-aws-wodle"}, "bucket_owner": "3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101", "bucket": "wazuh-cloudtrail", "time": "29/Apr/2021:08:57:58 +0000", "remote_ip": "213.194.148.169", "requester": "arn:aws:iam::166157441623:user/carlos.ridao", "request_id": "M5XS2MGJ6FEA5VTJ", "operation": "REST.GET.BUCKETVERSIONS", "key": "-", "request_uri": "GET /?versions&max-keys=1&encoding-type=url HTTP/1.1", "http_status": "200", "error_code": "-", "bytes_sent": "839", "object_sent": "-", "total_time": "54", "turn_around_time": "53", "referer": "-", "user_agent": "S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.991 Linux/4.9.230-0.1.ac.224.84.332.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.282-b08 java/1.8.0_282 vendor/Oracle_Corporation cfg/retry-mode/legacy", "version_id": "-", "host_id": "JyPaquNlVOP38Ap/6E0zqnh5Zj75+9KAv0weFdQChcLd6oaNZZxWyJUPhQgahDu4EHWDy7zQOsA=", "signature_version": "SigV4", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "authentication_type": "AuthHeader", "host_header": "wazuh-cloudtrail.s3.us-east-1.amazonaws.com", "tls_version": "TLSv1.2", "source": "s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80362')
        self.assertEqual(response.rule_level, 2)


    def test_silence_general_restgetobject(self) -> None:
        log = r'''
{"integration": "aws", "aws": {"log_info": {"aws_account_alias": "", "log_file": "access_logs/2021-04-29-09-41-37-6CFDED3B1BCCDEB1", "s3bucket": "wazuh-aws-wodle"}, "bucket_owner": "3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101", "bucket": "wazuh-cloudtrail", "time": "29/Apr/2021:08:57:58 +0000", "remote_ip": "213.194.148.169", "requester": "arn:aws:iam::166157441623:user/carlos.ridao", "request_id": "M5XS2MGJ6FEA5VTJ", "operation": "REST.GET.OBJECT", "key": "-", "request_uri": "GET /?versions&max-keys=1&encoding-type=url HTTP/1.1", "http_status": "200", "error_code": "-", "bytes_sent": "839", "object_sent": "-", "total_time": "54", "turn_around_time": "53", "referer": "-", "user_agent": "S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.991 Linux/4.9.230-0.1.ac.224.84.332.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.282-b08 java/1.8.0_282 vendor/Oracle_Corporation cfg/retry-mode/legacy", "version_id": "-", "host_id": "JyPaquNlVOP38Ap/6E0zqnh5Zj75+9KAv0weFdQChcLd6oaNZZxWyJUPhQgahDu4EHWDy7zQOsA=", "signature_version": "SigV4", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "authentication_type": "AuthHeader", "host_header": "wazuh-cloudtrail.s3.us-east-1.amazonaws.com", "tls_version": "TLSv1.2", "source": "s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80363')
        self.assertEqual(response.rule_level, 0)


    def test_operation_put(self) -> None:
        log = r'''
{"integration": "aws", "aws": {"log_info": {"aws_account_alias": "", "log_file": "access_logs/2021-04-29-09-38-27-8196FC2529DE67C3", "s3bucket": "wazuh-aws-wodle"}, "bucket_owner": "3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101", "bucket": "wazuh-cloudtrail", "time": "29/Apr/2021:08:52:31 +0000", "remote_ip": "-", "requester": "svc:cloudtrail.amazonaws.com", "request_id": "WF1XB03CFCAN420K", "operation": "REST.PUT.OBJECT", "key": "AWSLogs/166157441623/CloudTrail/us-west-1/2021/04/29/166157441623_CloudTrail_us-west-1_20210429T0840Z_QcTREycd1xiqQru5.json.gz", "request_uri": "PUT /AWSLogs/166157441623/CloudTrail/us-west-1/2021/04/29/166157441623_CloudTrail_us-west-1_20210429T0840Z_QcTREycd1xiqQru5.json.gz HTTP/1.1", "http_status": "200", "error_code": "-", "bytes_sent": "-", "object_sent": "2725", "total_time": "103", "turn_around_time": "15", "referer": "-", "user_agent": "-", "version_id": "-", "host_id": "FFcul1xzEVPZlAQn1tZoJq9SFEwudrfxAGWlYVbgM4OklyDqK8l9PNkSI30q17vwyGMUFQSyDGQ=", "signature_version": "SigV4", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "authentication_type": "AuthHeader", "host_header": "wazuh-cloudtrail.s3.us-east-1.amazonaws.com", "tls_version": "TLSv1.2", "source": "s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80364')
        self.assertEqual(response.rule_level, 3)


    def test_silence_events_when_s3_puts(self) -> None:
        log = r'''
{"integration":"aws","aws":{"log_info":{"aws_account_alias":"","log_file":"access_logs/2021-04-29-09-38-27-8196FC2529DE67C3","s3bucket":"wazuh-aws-wodle"},"bucket_owner":"3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101","bucket":"wazuh-cloudtrail","time":"29/Apr/2021:08:52:31 +0000","remote_ip":"-","requester":"svc:s3.amazonaws.com","request_id":"WF1XB03CFCAN420K","operation":"REST.PUT.OBJECT","key":"AWSLogs/166157441623/CloudTrail/us-west-1/2021/04/29/166157441623_CloudTrail_us-west-1_20210429T0840Z_QcTREycd1xiqQru5.json.gz","request_uri":"PUT /AWSLogs/166157441623/CloudTrail/us-west-1/2021/04/29/166157441623_CloudTrail_us-west-1_20210429T0840Z_QcTREycd1xiqQru5.json.gz HTTP/1.1","http_status":"200","error_code":"-","bytes_sent":"-","object_sent":"2725","total_time":"103","turn_around_time":"15","referer":"-","user_agent":"-","version_id":"-","host_id":"FFcul1xzEVPZlAQn1tZoJq9SFEwudrfxAGWlYVbgM4OklyDqK8l9PNkSI30q17vwyGMUFQSyDGQ=","signature_version":"SigV4","cipher_suite":"ECDHE-RSA-AES128-GCM-SHA256","authentication_type":"AuthHeader","host_header":"wazuh-cloudtrail.s3.us-east-1.amazonaws.com","tls_version":"TLSv1.2","source":"s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80365')
        self.assertEqual(response.rule_level, 0)


    def test_aws_s3_post_operation(self) -> None:
        log = r'''
{"integration":"aws","aws":{"log_info":{"aws_account_alias":"","log_file":"access_logs/2021-04-29-09-38-27-8196FC2529DE67C3","s3bucket":"wazuh-aws-wodle"},"bucket_owner":"3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101","bucket":"wazuh-cloudtrail","time":"29/Apr/2021:08:52:31 +0000","remote_ip":"-","requester":"svc:cloudtrail.amazonaws.com","request_id":"WF1XB03CFCAN420K","operation":"REST.POST.OBJECT","key":"AWSLogs/166157441623/CloudTrail/us-west-1/2021/04/29/166157441623_CloudTrail_us-west-1_20210429T0840Z_QcTREycd1xiqQru5.json.gz","request_uri":"PUT /AWSLogs/166157441623/CloudTrail/us-west-1/2021/04/29/166157441623_CloudTrail_us-west-1_20210429T0840Z_QcTREycd1xiqQru5.json.gz HTTP/1.1","http_status":"200","error_code":"-","bytes_sent":"-","object_sent":"2725","total_time":"103","turn_around_time":"15","referer":"-","user_agent":"-","version_id":"-","host_id":"FFcul1xzEVPZlAQn1tZoJq9SFEwudrfxAGWlYVbgM4OklyDqK8l9PNkSI30q17vwyGMUFQSyDGQ=","signature_version":"SigV4","cipher_suite":"ECDHE-RSA-AES128-GCM-SHA256","authentication_type":"AuthHeader","host_header":"wazuh-cloudtrail.s3.us-east-1.amazonaws.com","tls_version":"TLSv1.2","source":"s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80366')
        self.assertEqual(response.rule_level, 2)


    def test_generic_error(self) -> None:
        log = r'''
{"integration": "aws", "aws": {"log_info": {"aws_account_alias": "", "log_file": "access_logs/2021-04-29-09-47-05-689ED56B49777287", "s3bucket": "wazuh-aws-wodle"}, "bucket_owner": "3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101", "bucket": "wazuh-cloudtrail", "time": "29/Apr/2021:08:47:53 +0000", "remote_ip": "92.57.74.50", "requester": "arn:aws:iam::166157441623:user/david.iglesias", "request_id": "T3BJ3QVNEB2XNQZ6", "operation": "REST.GET.ENCRYPTION", "key": "-", "request_uri": "GET /wazuh-cloudtrail?encryption= HTTP/1.1", "http_status": "404", "error_code": "ServerSideEncryptionConfigurationNotFoundError", "bytes_sent": "359", "object_sent": "-", "total_time": "28", "turn_around_time": "-", "referer": "-", "user_agent": "S3Console/0.4, aws-internal/3 aws-sdk-java/1.11.991 Linux/4.9.230-0.1.ac.224.84.332.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.282-b08 java/1.8.0_282 vendor/Oracle_Corporation cfg/retry-mode/legacy", "version_id": "-", "host_id": "aWts5+h5vGMYypTnH/uUuT+k1dt+C6r/qa9WqxHmYfv58SJlkEXi2EvgnOJcaIpTGs10FzFAS58=", "signature_version": "SigV4", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "authentication_type": "AuthHeader", "host_header": "s3.amazonaws.com", "tls_version": "TLSv1.2", "source": "s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80367')
        self.assertEqual(response.rule_level, 5)


    def test_access_denied(self) -> None:
        log = r'''
{"integration": "aws", "aws": {"log_info": {"aws_account_alias": "", "log_file": "access_logs/2021-04-29-09-16-56-7297D7461A5CBE77", "s3bucket": "wazuh-aws-wodle"}, "bucket_owner": "3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101", "bucket": "wazuh-cloudtrail", "time": "29/Apr/2021:08:59:21 +0000", "remote_ip": "213.194.148.169", "requester": "-", "request_id": "0EC86NTN8Y97ACDW", "operation": "REST.GET.OBJECT", "key": "favicon.ico", "request_uri": "GET /favicon.ico HTTP/1.1", "http_status": "403", "error_code": "AccessDenied", "bytes_sent": "243", "object_sent": "-", "total_time": "13", "turn_around_time": "-", "referer": "https://wazuh-cloudtrail.s3.us-east-1.amazonaws.com/AWSLogs/166157441623/CloudTrail/us-east-1/2021/04/29/166157441623_CloudTrail_us-east-1_20210429T0000Z_G1vOYSX8NpPp1yb2.json.gz?response-content-disposition=inline&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEPn%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJIMEYCIQCKokRRbfrUEbPdYHNW%2BNG4DRAi3gxlcVsWTBswmTEj4gIhAIH%2B2OXjpVR9j2kumUcXz%2FJSy5pqDoSOFuigMy%2FwNtacKpEDCHIQABoMMTY2MTU3NDQxNjIzIgwJLRknE%2B7%2FMtpQ7rUq7gLTQog%2B8r%2F%2FR4le%2F%2F%2F15QyZuu9VPuHbUab77oPR4XudNmUGS0rTEEuL7y6XCb22M8piKNem2aMkywEMwp1Z6uMfps8R16H35r%2Bj6K5Ow84yyHHlDH0H9cynTaAweFH0Lskub59fBwRBj9COEQmylKjthLqEBhSsg99D%2ByxzmVT15OHO%2BFJZycgELyK%2FZ32jRhDIG0JL1Z%2F41VRUZJDGnvjVQYWfr3rZIRTQsAEghJmxRYIgLL51IzR9yPGYo9kfG4l9dxP9bHJkuyo5754FVaoQyNdNNmYyrQc2BORXskRQgIHAx937INaQhWFOp2w6MZnVChbb8snybpTs8vXbqfxrgyBkEop%2BdNtymj8c%2FSZPssv5S1kqPD1Avbkn14lipILMrS1ujSW0R5y%2F37NagNJ2xjA35iy0zYrlvU7ipx%2FwVZESyAA0Jb%2F8JN6f6xV9NdVXRdZC9MDZpOX%2Bv6gm%2FVzdVukorBiFlYIxbJJLleUw%2BN%2BphAY6sgJndd0zSELg%2Fo07zRYq0AbvOdns6HtcQbAAyUBVQsA2GXhl5zYto%2BqQ97TNcez5sYpOxylplQNcu0xeTFasufucPQnEaBWQAgRhyKZGhORiTi1aIprdg5cvT1hBf0ttS78YLVNOLZQCFp7NdZAVOtJXlOrz7TpIiwQm1OxqzFSgnn13PNHrFjiNEBgk16207083RTIkioB%2BNCzLpRluhURbfSNiDWb15WvxLchIY2o5L9cdyr1Ih0BuymW09snZFulWGkqImpby%2FEAfKMGCgtM2zf4lVW%2BIAh6%2BlGtHAwir7dx2sElB3I4yPUfL%2FyjzYJlstmoSng4cCiVW6ljTXtNUvwDYsI10tynFpzLagsL%2B8Cde%2BF4BtRrCpL7gwSN5fzQOF%2FGQZrBPpFlZlp5GEOoltp4%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20210429T085920Z&X-Amz-SignedHeaders=host&X-Amz-Expires=300&X-Amz-Credential=ASIASNL6BLJLX5CGRFB7%2F20210429%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=f6b108ea19ce136eef97ac65cc60d4d8b644f44a60f9fed3f108e85655d938ab", "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Safari/537.36", "version_id": "-", "host_id": "IzZPYtJFGFHjl+wNZa73b/d/xowqZFBZI5Ayxr+pT7qgVIzSJDOgPFLUWzB+huF2PMsu2T5z1H0=", "signature_version": "-", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "authentication_type": "-", "host_header": "wazuh-cloudtrail.s3.us-east-1.amazonaws.com", "tls_version": "TLSv1.2", "source": "s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80368')
        self.assertEqual(response.rule_level, 5)


    def test_aws_s3_authentication_failure(self) -> None:
        log = r'''
{"integration":"aws","aws":{"log_info":{"aws_account_alias":"","log_file":"access_logs/2021-04-29-09-16-56-7297D7461A5CBE77","s3bucket":"wazuh-aws-wodle"},"bucket_owner":"3ab1235e25ea9e94ff9b7e4e379ba6b0c872cd36c096e1ac8cce7df433b47101","bucket":"wazuh-cloudtrail","time":"29/Apr/2021:08:59:21 +0000","remote_ip":"213.194.148.169","requester":"-","request_id":"0EC86NTN8Y97ACDW","operation":"REST.GET.OBJECT","key":"favicon.ico","request_uri":"GET /favicon.ico HTTP/1.1","http_status":"403","error_code":"InvalidSecurity","bytes_sent":"243","object_sent":"-","total_time":"13","turn_around_time":"-","referer":"https://wazuh-cloudtrail.s3.us-east-1.amazonaws.com/AWSLogs/166157441623/CloudTrail/us-east-1/2021/04/29/166157441623_CloudTrail_us-east-1_20210429T0000Z_G1vOYSX8NpPp1yb2.json.gz?response-content-disposition=inline&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEPn%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCWV1LXdlc3QtMyJIMEYCIQCKokRRbfrUEbPdYHNW%2BNG4DRAi3gxlcVsWTBswmTEj4gIhAIH%2B2OXjpVR9j2kumUcXz%2FJSy5pqDoSOFuigMy%2FwNtacKpEDCHIQABoMMTY2MTU3NDQxNjIzIgwJLRknE%2B7%2FMtpQ7rUq7gLTQog%2B8r%2F%2FR4le%2F%2F%2F15QyZuu9VPuHbUab77oPR4XudNmUGS0rTEEuL7y6XCb22M8piKNem2aMkywEMwp1Z6uMfps8R16H35r%2Bj6K5Ow84yyHHlDH0H9cynTaAweFH0Lskub59fBwRBj9COEQmylKjthLqEBhSsg99D%2ByxzmVT15OHO%2BFJZycgELyK%2FZ32jRhDIG0JL1Z%2F41VRUZJDGnvjVQYWfr3rZIRTQsAEghJmxRYIgLL51IzR9yPGYo9kfG4l9dxP9bHJkuyo5754FVaoQyNdNNmYyrQc2BORXskRQgIHAx937INaQhWFOp2w6MZnVChbb8snybpTs8vXbqfxrgyBkEop%2BdNtymj8c%2FSZPssv5S1kqPD1Avbkn14lipILMrS1ujSW0R5y%2F37NagNJ2xjA35iy0zYrlvU7ipx%2FwVZESyAA0Jb%2F8JN6f6xV9NdVXRdZC9MDZpOX%2Bv6gm%2FVzdVukorBiFlYIxbJJLleUw%2BN%2BphAY6sgJndd0zSELg%2Fo07zRYq0AbvOdns6HtcQbAAyUBVQsA2GXhl5zYto%2BqQ97TNcez5sYpOxylplQNcu0xeTFasufucPQnEaBWQAgRhyKZGhORiTi1aIprdg5cvT1hBf0ttS78YLVNOLZQCFp7NdZAVOtJXlOrz7TpIiwQm1OxqzFSgnn13PNHrFjiNEBgk16207083RTIkioB%2BNCzLpRluhURbfSNiDWb15WvxLchIY2o5L9cdyr1Ih0BuymW09snZFulWGkqImpby%2FEAfKMGCgtM2zf4lVW%2BIAh6%2BlGtHAwir7dx2sElB3I4yPUfL%2FyjzYJlstmoSng4cCiVW6ljTXtNUvwDYsI10tynFpzLagsL%2B8Cde%2BF4BtRrCpL7gwSN5fzQOF%2FGQZrBPpFlZlp5GEOoltp4%3D&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20210429T085920Z&X-Amz-SignedHeaders=host&X-Amz-Expires=300&X-Amz-Credential=ASIASNL6BLJLX5CGRFB7%2F20210429%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=f6b108ea19ce136eef97ac65cc60d4d8b644f44a60f9fed3f108e85655d938ab","user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Safari/537.36","version_id":"-","host_id":"IzZPYtJFGFHjl+wNZa73b/d/xowqZFBZI5Ayxr+pT7qgVIzSJDOgPFLUWzB+huF2PMsu2T5z1H0=","signature_version":"-","cipher_suite":"ECDHE-RSA-AES128-GCM-SHA256","authentication_type":"-","host_header":"wazuh-cloudtrail.s3.us-east-1.amazonaws.com","tls_version":"TLSv1.2","source":"s3_server_access"}}
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '80370')
        self.assertEqual(response.rule_level, 5)

