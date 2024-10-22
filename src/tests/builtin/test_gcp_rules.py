#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from gcp.ini
class TestGcpRules(unittest.TestCase):

    def test_gcp_generic_info(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.monitoring.v3.MetricService.ListTimeSeries","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65040')
        self.assertEqual(response.rule_level, 2)


    def test_gcp_generic_warning(self) -> None:
        log = '''{"integration":"gcp","gcp":{"httpRequest":{"latency":"0.000864s","remoteIp":"YY.YY.YY.YY","requestMethod":"GET","requestSize":"385","requestUrl":"http://XX.XX.XX.XX/favicon.ico","responseSize":"488","status":502,"userAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"},"insertId":"1mtxf1hf2c4idk","jsonPayload":{"@type":"type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry","statusDetails":"failed_to_pick_backend"},"logName":"projects/wazuh-dev-xxxxxx/logs/requests","receiveTimestamp":"2021-06-09T15:17:25.473538144Z","resource":{"labels":{"backend_service_name":"framework-load-balancer-backend-test","forwarding_rule_name":"framework-load-balancer-backend-test","project_id":"wazuh-dev-xxxxxx","target_proxy_name":"framework-load-balancer-test-target-proxy","url_map_name":"framework-load-balancer-test","zone":"global"},"type":"http_load_balancer"},"severity":"WARNING","spanId":"ab6c36e7fc60f24e","timestamp":"2021-06-09T15:17:24.408864Z","trace":"projects/wazuh-dev-xxxxxx/traces/68183a7cda548ce0e79207099a1fea58"}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65041')
        self.assertEqual(response.rule_level, 5)


    def test_gcp_generic_notice(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"gce_autoscaler","labels":{"project_id":"wazuh-dev-258815","location":"us-east1-b","autoscaler_id":"6792866887804055843"}},"protoPayload":{"requestMetadata":{"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36,gzip(gfe),gzip(gfe)","callerIp":"213.194.153.13"},"request":{"@type":"type.googleapis.com/compute.autoscalers.insert"},"authenticationInfo":{"principalEmail":"carlos.ridao@wazuh.com"},"@type":"type.googleapis.com/google.cloud.audit.AuditLog","methodName":"beta.compute.autoscalers.insert","resourceName":"projects/wazuh-dev-258815/zones/us-east1-b/autoscalers/framework-test-instance-group-1","serviceName":"compute.googleapis.com"},"receiveTimestamp":"2021-06-08T11:09:02.399625057Z","operation":{"last":"true","producer":"compute.googleapis.com","id":"operation-1623150539438-5c43f2f51f7fe-84f4728e-ac44be61"},"insertId":"suy3z6d14pw","timestamp":"2021-06-08T11:09:02.032595Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65042')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_vpc_firewall_deny_rule_triggered(self) -> None:
        log = '''{"integration":"gcp","gcp":{"insertId":"6dxcl6g15v9cee","jsonPayload":{"connection":{"dest_ip":"10.142.0.2","dest_port":22,"protocol":6,"src_ip":"XX.XX.XX.XX","src_port":43710},"disposition":"DENIED","instance":{"project_id":"wazuh-dev-XXXXXX","region":"us-east1","vm_name":"framework-vpc-flow-test-instance","zone":"us-east1-b"},"rule_details":{"action":"DENY","direction":"INGRESS","ip_port_info":[{"ip_protocol":"TCP","port_range":["22"]}],"priority":65534,"reference":"network:default/firewall:default-deny-ssh","source_range":["0.0.0.0/0"]},"vpc":{"project_id":"wazuh-dev-XXXXXX","subnetwork_name":"default","vpc_name":"default"}},"logName":"projects/wazuh-dev-XXXXXX/logs/compute.googleapis.com%2Ffirewall","receiveTimestamp":"2021-06-04T13:27:43.45097863Z","resource":{"labels":{"location":"us-east1-b","project_id":"wazuh-dev-XXXXXX","subnetwork_id":"6133410668509430049","subnetwork_name":"default"},"type":"gce_subnetwork"},"timestamp":"2021-06-04T13:27:35.794717819Z"}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65048')
        self.assertEqual(response.rule_level, 5)


    def test_gcp_vpc_firewall_allow_rule_triggered(self) -> None:
        log = '''{"integration":"gcp","gcp":{"insertId":"6dxcl6g15v9cee","jsonPayload":{"connection":{"dest_ip":"10.142.0.2","dest_port":22,"protocol":6,"src_ip":"XX.XX.XX.XX","src_port":43710},"disposition":"ALLOWED","instance":{"project_id":"wazuh-dev-XXXXXX","region":"us-east1","vm_name":"framework-vpc-flow-test-instance","zone":"us-east1-b"},"rule_details":{"action":"ALLOW","direction":"INGRESS","ip_port_info":[{"ip_protocol":"TCP","port_range":["22"]}],"priority":65534,"reference":"network:default/firewall:default-allow-ssh","source_range":["0.0.0.0/0"]},"vpc":{"project_id":"wazuh-dev-XXXXXX","subnetwork_name":"default","vpc_name":"default"}},"logName":"projects/wazuh-dev-XXXXXX/logs/compute.googleapis.com%2Ffirewall","receiveTimestamp":"2021-06-04T13:27:43.45097863Z","resource":{"labels":{"location":"us-east1-b","project_id":"wazuh-dev-XXXXXX","subnetwork_id":"6133410668509430049","subnetwork_name":"default"},"type":"gce_subnetwork"},"timestamp":"2021-06-04T13:27:35.794717819Z"}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65049')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_vpc_flow_rules_grouped(self) -> None:
        log = '''{"integration":"gcp","gcp":{"insertId":"g3n55zfjeyg2i","jsonPayload":{"bytes_sent":"8","connection":{"dest_ip":"ff02::2","protocol":58,"src_ip":"XXXXXXXXXXXXXX"},"dest_location":{},"end_time":"2021-06-04T11:18:46.770486824Z","packets_sent":"1","reporter":"SRC","src_instance":{"project_id":"wazuh-dev-XXXXXX","region":"us-east1","vm_name":"framework-vpc-flow-test-instance","zone":"us-east1-b"},"src_vpc":{"project_id":"wazuh-dev-XXXXXX","subnetwork_name":"default","vpc_name":"default"},"start_time":"2021-06-04T11:18:46.770486824Z"},"logName":"projects/wazuh-dev-XXXXXX/logs/compute.googleapis.com%2Fvpc_flows","receiveTimestamp":"2021-06-04T11:19:10.440812789Z","resource":{"labels":{"location":"us-east1-b","project_id":"wazuh-dev-XXXXXX","subnetwork_id":"6133410668509430049","subnetwork_name":"default"},"type":"gce_subnetwork"},"timestamp":"2021-06-04T11:19:10.440812789Z"}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65050')
        self.assertEqual(response.rule_level, 2)


    def test_collection_gcp_pub_sub_subscription_creation(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"google.pubsub.v1.Subscriber.CreateSubscription","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65051')
        self.assertEqual(response.rule_level, 3)


    def test_collection_gcp_pub_sub_topic_creation(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:05.408091615Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Topic","name":"projects/wazuh-dev-258815/topics/threatintel-gcp"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815","permission":"pubsub.topics.create","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Topic","name":"projects/wazuh-dev-258815/topics/threatintel-gcp"},"methodName":"google.pubsub.v1.Publisher.CreateTopic","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:09.239238903Z","insertId":"vmyzdgc4u3","timestamp":"2021-06-10T15:07:05.400577592Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65052')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_firewall_rule_created(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"gce_firewall_rule","labels":{"project_id":"wazuh-dev-258815","firewall_rule_id":"6352627401320071455"}},"protoPayload":{"requestMetadata":{"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36,gzip(gfe),gzip(gfe)","callerIp":"213.194.154.232"},"request":{"@type":"type.googleapis.com/compute.firewalls.patch"},"authenticationInfo":{"principalEmail":"carlos.ridao@wazuh.com"},"@type":"type.googleapis.com/google.cloud.audit.AuditLog","resourceOriginalState":{"logConfig":{"metadata":"INCLUDE_ALL_METADATA","enable":"false"},"@type":"compute.googleapis.com/patch.state","description":"Allow internal traffic on the default network","priority":"65534","network":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/networks/default","selfLink":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/firewalls/default-allow-internal","sourceRanges":["10.128.0.0/9"],"selfLinkWithId":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/firewalls/6352627401320071455","creationTimestamp":"2021-05-31T12:58:40.887-07:00","name":"default-allow-internal","alloweds":[{"IPProtocol":"tcp","ports":["0-65535"]},{"IPProtocol":"udp","ports":["0-65535"]},{"IPProtocol":"icmp"}],"disabled":"false","id":"6352627401320071455","enableLogging":"false","direction":"INGRESS"},"methodName":"v1.compute.firewalls.insert","resourceName":"projects/wazuh-dev-258815/global/firewalls/default-allow-internal","serviceName":"compute.googleapis.com"},"receiveTimestamp":"2021-06-04T13:26:50.156887429Z","operation":{"last":"true","producer":"compute.googleapis.com","id":"operation-1622813206787-5c3f0a4ba3417-3838b401-5fcfe6fd"},"insertId":"qx0fpcdfo5k","timestamp":"2021-06-04T13:26:49.79784Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65053')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_firewall_rule_deleted(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"gce_firewall_rule","labels":{"project_id":"wazuh-dev-258815","firewall_rule_id":"6352627401320071455"}},"protoPayload":{"requestMetadata":{"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36,gzip(gfe),gzip(gfe)","callerIp":"213.194.154.232"},"request":{"@type":"type.googleapis.com/compute.firewalls.patch"},"authenticationInfo":{"principalEmail":"carlos.ridao@wazuh.com"},"@type":"type.googleapis.com/google.cloud.audit.AuditLog","resourceOriginalState":{"logConfig":{"metadata":"INCLUDE_ALL_METADATA","enable":"false"},"@type":"compute.googleapis.com/patch.state","description":"Allow internal traffic on the default network","priority":"65534","network":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/networks/default","selfLink":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/firewalls/default-allow-internal","sourceRanges":["10.128.0.0/9"],"selfLinkWithId":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/firewalls/6352627401320071455","creationTimestamp":"2021-05-31T12:58:40.887-07:00","name":"default-allow-internal","alloweds":[{"IPProtocol":"tcp","ports":["0-65535"]},{"IPProtocol":"udp","ports":["0-65535"]},{"IPProtocol":"icmp"}],"disabled":"false","id":"6352627401320071455","enableLogging":"false","direction":"INGRESS"},"methodName":"v1.compute.firewalls.delete","resourceName":"projects/wazuh-dev-258815/global/firewalls/default-allow-internal","serviceName":"compute.googleapis.com"},"receiveTimestamp":"2021-06-04T13:26:50.156887429Z","operation":{"last":"true","producer":"compute.googleapis.com","id":"operation-1622813206787-5c3f0a4ba3417-3838b401-5fcfe6fd"},"insertId":"qx0fpcdfo5k","timestamp":"2021-06-04T13:26:49.79784Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65054')
        self.assertEqual(response.rule_level, 3)


    def test_defense_evasion_gcp_firewall_rule_modified(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"gce_firewall_rule","labels":{"project_id":"wazuh-dev-258815","firewall_rule_id":"6352627401320071455"}},"protoPayload":{"requestMetadata":{"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36,gzip(gfe),gzip(gfe)","callerIp":"213.194.154.232"},"request":{"@type":"type.googleapis.com/compute.firewalls.patch"},"authenticationInfo":{"principalEmail":"carlos.ridao@wazuh.com"},"@type":"type.googleapis.com/google.cloud.audit.AuditLog","resourceOriginalState":{"logConfig":{"metadata":"INCLUDE_ALL_METADATA","enable":"false"},"@type":"compute.googleapis.com/patch.state","description":"Allow internal traffic on the default network","priority":"65534","network":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/networks/default","selfLink":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/firewalls/default-allow-internal","sourceRanges":["10.128.0.0/9"],"selfLinkWithId":"https://www.googleapis.com/compute/v1/projects/wazuh-dev-258815/global/firewalls/6352627401320071455","creationTimestamp":"2021-05-31T12:58:40.887-07:00","name":"default-allow-internal","alloweds":[{"IPProtocol":"tcp","ports":["0-65535"]},{"IPProtocol":"udp","ports":["0-65535"]},{"IPProtocol":"icmp"}],"disabled":"false","id":"6352627401320071455","enableLogging":"false","direction":"INGRESS"},"methodName":"v1.compute.firewalls.patch","resourceName":"projects/wazuh-dev-258815/global/firewalls/default-allow-internal","serviceName":"compute.googleapis.com"},"receiveTimestamp":"2021-06-04T13:26:50.156887429Z","operation":{"last":"true","producer":"compute.googleapis.com","id":"operation-1622813206787-5c3f0a4ba3417-3838b401-5fcfe6fd"},"insertId":"qx0fpcdfo5k","timestamp":"2021-06-04T13:26:49.79784Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65055')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_logging_bucket_deleted(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.logging.v3.ConfigServiceV1.DeleteBucket","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65056')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_logging_sink_deleted(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.logging.v3.ConfigServiceV1.DeleteSink","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65057')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_pub_sub_subscription_deleted(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"google.pubsub.v1.Subscriber.DeleteSubscription","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65058')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_pub_sub_topic_deleted(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"google.pubsub.v1.Publisher.DeleteTopic","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65059')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_storage_bucket_configuration_modified(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"storage.buckets.update","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65060')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_storage_bucket_permissions_modified(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"storage.setIamPermissions","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65061')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_logging_sink_modified(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.logging.v3.ConfigServiceV1.UpdateSink","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65062')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_iam_role_deleted(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.iam.admin.v3.DeleteRole","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65063')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_iam_service_account_deleted(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.iam.admin.v3.DeleteServiceAccount","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65064')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_service_account_disabled(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.iam.admin.v3.DisableServiceAccount","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65065')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_storage_bucket_deleted(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"storage.buckets.delete","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65066')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_virtual_private_cloud_vpc_network_deleted(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"v3.compute.networks.delete","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65067')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_virtual_private_cloud_vpc_route_created(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"v3.compute.routes.insert","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65068')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_virtual_private_cloud_vpc_route_deleted(self) -> None:
        log = '''{"gcp":{"severity":"NOTICE","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Factivity","resource":{"type":"pubsub_topic","labels":{"project_id":"wazuh-dev-258815","topic_id":"projects/wazuh-dev-258815/topics/threatintel-gcp"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-10T15:07:09.68842532Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"authenticationInfo":{"principalSubject":"user:javier.bejar@wazuh.com","principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"projects/wazuh-dev-258815/topics/threatintel-gcp","permission":"pubsub.topics.attachSubscription","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","response":{"@type":"type.googleapis.com/google.pubsub.v1.Subscription","messageRetentionDuration":"604800s","name":"projects/wazuh-dev-258815/subscriptions/threatintel-gcp-sub","topic":"projects/wazuh-dev-258815/topics/threatintel-gcp","ackDeadlineSeconds":"10"},"methodName":"v3.compute.routes.delete","resourceName":"projects/wazuh-dev-258815/topics/threatintel-gcp","serviceName":"pubsub.googleapis.com"},"receiveTimestamp":"2021-06-10T15:07:15.879792037Z","insertId":"jzee3lb9j","timestamp":"2021-06-10T15:07:09.68170948Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65069')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_new_service_account_created(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.iam.admin.v3.CreateServiceAccount","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65070')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_new_key_is_created_for_a_service_account(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.iam.admin.v3.CreateServiceAccountKey","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65071')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_identity_and_access_management_iam_service_account_key_deleted(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.iam.admin.v3.DeleteServiceAccountKey","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65072')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_identity_and_access_management_iam_custom_role_created(self) -> None:
        log = '''{"gcp":{"severity":"INFO","logName":"projects/wazuh-dev-258815/logs/cloudaudit.googleapis.com%2Fdata_access","resource":{"type":"audited_resource","labels":{"method":"google.monitoring.v3.MetricService.ListTimeSeries","project_id":"wazuh-dev-258815","service":"monitoring.googleapis.com"}},"protoPayload":{"requestMetadata":{"requestAttributes":{"time":"2021-06-11T09:35:18.077583788Z"},"callerSuppliedUserAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36,gzip(gfe)","callerIp":"80.39.210.176"},"request":{"filter":"metric.type=\"pubsub.googleapis.com/topic/send_message_operation_count\" AND resource.labels.project_id=\"wazuh-dev-258815\" AND resource.labels.topic_id=\"wazuh-gcloud-blog-topic\" AND resource.type=\"pubsub_topic\"","@type":"type.googleapis.com/google.monitoring.v3.ListTimeSeriesRequest","name":"projects/wazuh-dev-258815"},"authenticationInfo":{"principalEmail":"javier.bejar@wazuh.com"},"authorizationInfo":[{"resource":"769054035614","permission":"monitoring.timeSeries.list","resourceAttributes":{},"granted":true}],"@type":"type.googleapis.com/google.cloud.audit.AuditLog","numResponseItems":"1","methodName":"google.iam.admin.v3.CreateRole","resourceName":"projects/wazuh-dev-258815","serviceName":"monitoring.googleapis.com"},"receiveTimestamp":"2021-06-11T09:35:18.35940193Z","insertId":"s1gmn4e7xlr1","timestamp":"2021-06-11T09:35:18.077460268Z"},"integration":"gcp"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65073')
        self.assertEqual(response.rule_level, 3)


    def test_gcp_usage(self) -> None:
        log = '''{"integration": "gcp", "gcp": {"time_micros": "1623657113850001", "c_ip": "34.75.50.245", "c_ip_type": "1", "c_ip_region": "", "cs_method": "GET", "cs_uri": "/download/storage/v1/b/framework-test-bucket/o/usage-logs_usage_2021_06_11_14_00_00_0deb315d529495e45e_v0?alt=media&generation=1623445458746803", "sc_status": "206", "cs_bytes": "0", "sc_bytes": "644", "time_taken_micros": "141000", "cs_host": "storage.googleapis.com", "cs_referer": "", "cs_user_agent": "DataflowBatchWorkerHarness Google-API-Java-Client/1.30.10 Google-HTTP-Java-Client/1.36.0 (gzip)", "s_request_id": "ABg5-UwwFhsTGuOn2WpJdUzroNMTNuh-IabN-9XKEwnEJMi3Hcv_o96mM8lqKU3wWWGko5RL4pEoaepuizcP_NQIKhw", "cs_operation": "storage.objects.get", "cs_bucket": "framework-test-bucket", "cs_object": "usage-logs_usage_2021_06_11_14_00_00_0deb315d529495e45e_v0", "source": "gcp_bucket"}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65074')
        self.assertEqual(response.rule_level, 2)


    def test_gcp_storage(self) -> None:
        log = '''{"integration": "gcp", "gcp": {"bucket": "bucket_name", "storage_byte_hours": "15674"}}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65075')
        self.assertEqual(response.rule_level, 2)

