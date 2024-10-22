#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from gitlab.ini
class TestGitlabRules(unittest.TestCase):

    def test_gitlab_production_1(self) -> None:
        log = '''{"method":"GET","path":"/gitlab/gitlab-ce/issues/1234","format":"html","controller":"Projects::IssuesController","action":"show","status":200,"duration":229.03,"view":174.07,"db":13.24,"time":"2017-08-08T20:15:54.821Z","params":[{"key":"param_key","value":"param_value"}],"remote_ip":"18.245.0.1","user_id":1,"username":"admin","gitaly_calls":76,"gitaly_duration":7.41,"queue_duration": 112.47}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65600')
        self.assertEqual(response.rule_level, 3)


    def test_error_couldnt_complete_push_request(self) -> None:
        log = '''{"method":"PUSH","path":"/gitlab/gitlab-ce/issues/1234","format":"html","controller":"Projects::IssuesController","action":"show","status":400,"duration":229.03,"view":174.07,"db":13.24,"time":"2017-08-08T20:15:54.821Z","params":[{"key":"param_key","value":"param_value"}],"remote_ip":"18.245.0.1","user_id":1,"username":"admin","gitaly_calls":76,"gitaly_duration":7.41,"queue_duration": 112.47}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65601')
        self.assertEqual(response.rule_level, 5)


    def test_redirection_the_push_request_has_more_than_one_possible_response(self) -> None:
        log = '''{"method":"PUSH","path":"/gitlab/gitlab-ce/issues/1234","format":"html","controller":"Projects::IssuesController","action":"show","status":300,"duration":229.03,"view":174.07,"db":13.24,"time":"2017-08-08T20:15:54.821Z","params":[{"key":"param_key","value":"param_value"}],"remote_ip":"18.245.0.1","user_id":1,"username":"admin","gitaly_calls":76,"gitaly_duration":7.41,"queue_duration": 112.47}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65602')
        self.assertEqual(response.rule_level, 5)


    def test_user_administrator_was_created(self) -> None:
        log = '''October 06, 2014 11:56: User "Administrator" (admin@example.com) was created'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-12-application-log')
        self.assertEqual(response.rule_id, '65603')
        self.assertEqual(response.rule_level, 3)


    def test_documentcloud_created_a_new_project(self) -> None:
        log = '''October 06, 2014 11:56: Documentcloud created a new project "Documentcloud / Underscore"'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-12-application-log')
        self.assertEqual(response.rule_id, '65604')
        self.assertEqual(response.rule_level, 3)


    def test_user_dummy_was_removed(self) -> None:
        log = '''October 06, 2014 11:56: User "dummy" (dummy@gmail.com) was removed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-12-application-log')
        self.assertEqual(response.rule_id, '65605')
        self.assertEqual(response.rule_level, 3)


    def test_project_project133_was_removed(self) -> None:
        log = '''October 07, 2014 11:25: Project "project133" was removed'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-12-application-log')
        self.assertEqual(response.rule_id, '65606')
        self.assertEqual(response.rule_level, 3)


    def test_error_sending_message(self) -> None:
        log = '''{"severity":"ERROR","time":"2018-09-06T14:56:20.439Z","service_class":"JiraService","project_id":8,"project_path":"h5bp/html5-boilerplate","message":"Error sending message","client_url":"http://jira.gitlap.com:8080","error":"execution expired"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65607')
        self.assertEqual(response.rule_level, 5)


    def test_successfully_posted(self) -> None:
        log = '''{"severity":"INFO","time":"2018-09-06T17:15:16.365Z","service_class":"JiraService","project_id":3,"project_path":"namespace2/project2","message":"Successfully posted","client_url":"http://jira.example.com"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65608')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_kubernetes_1_error_unauthorized(self) -> None:
        log = '''{"severity":"ERROR","time":"2018-11-23T15:14:54.652Z","exception":"Kubeclient::HttpError","error_code":401,"service":"Clusters::Applications::CheckInstallationProgressService","app_id":14,"project_ids":[1],"group_ids":[],"message":"Unauthorized"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65609')
        self.assertEqual(response.rule_level, 5)


    def test_gitlab_kubernetes_2_info(self) -> None:
        log = '''{"severity":"INFO","time":"2018-11-23T15:42:11.647Z","exception":"Kubeclient::HttpError","error_code":null,"service":"Clusters::Applications::InstallService","app_id":2,"project_ids":[19],"group_ids":[],"message":"SSL_connect returned=1 errno=0 state=error: certificate verify failed (unable to get local issuer certificate)"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65610')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_githost_error(self) -> None:
        log = '''{"severity":"ERROR","time":"2019-07-19T22:16:12.528Z","correlation_id":"FeGxww5Hj64","message":"Command failed [1]: /usr/bin/git --git-dir=/Users/vsizov/gitlab-development-kit/gitlab/tmp/tests/gitlab-satellites/group184/gitlabhq/.git --work-tree=/Users/vsizov/gitlab-development-kit/gitlab/tmp/tests/gitlab-satellites/group184/gitlabhq merge --no-ff -mMerge branch 'feature_conflict' into 'feature' source/feature_conflict\n\nerror: failed to push some refs to '/Users/vsizov/gitlab-development-kit/repositories/gitlabhq/gitlab_git.git'"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65611')
        self.assertEqual(response.rule_level, 5)


    def test_gitlab_audit_info_1(self) -> None:
        log = '''{"severity":"INFO","time":"2018-10-17T17:38:22.523Z","author_id":3,"entity_id":2,"entity_type":"Project","change":"visibility","from":"Private","to":"Public","author_name":"John Doe4","target_id":2,"target_type":"Project","target_details":"namespace2/project2"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65612')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_audit_info_2(self) -> None:
        log = '''{"severity":"INFO","time":"2018-10-17T17:38:22.830Z","author_id":5,"entity_id":3,"entity_type":"Project","change":"name","from":"John Doe7 / project3","to":"John Doe7 / new name","author_name":"John Doe6","target_id":3,"target_type":"Project","target_details":"namespace3/project3"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65612')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_audit_info_3(self) -> None:
        log = '''{"severity":"INFO","time":"2018-10-17T17:38:23.175Z","author_id":7,"entity_id":4,"entity_type":"Project","change":"path","from":"","to":"namespace4/newpath","author_name":"John Doe8","target_id":4,"target_type":"Project","target_details":"namespace4/newpath"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65612')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_sidekiq_2_info(self) -> None:
        log = '''2014-06-10T18:18:26Z 14299 TID-55uqo INFO: Booting Sidekiq 3.0.0 with redis options {:url=>"redis://localhost:6379/0", :namespace=>"sidekiq"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-sidekiq')
        self.assertEqual(response.rule_id, '65614')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_sidekiq_1_error(self) -> None:
        log = '''2014-06-10T07:55:20Z 2037 TID-tm504 ERROR: /opt/bitnami/apps/discourse/htdocs/vendor/bundle/ruby/1.9.1/gems/redis-3.0.7/lib/redis/client.rb:228:in `read''''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-sidekiq')
        self.assertEqual(response.rule_id, '65615')
        self.assertEqual(response.rule_level, 5)


    def test_gitlab_sidekiq_3_info(self) -> None:
        log = '''{"severity":"INFO","time":"2018-04-03T22:57:22.071Z","queue":"cronjob:update_all_mirrors","args":[],"class":"UpdateAllMirrorsWorker","retry":false,"queue_namespace":"cronjob","jid":"06aeaa3b0aadacf9981f368e","created_at":"2018-04-03T22:57:21.930Z","enqueued_at":"2018-04-03T22:57:21.931Z","pid":10077,"message":"UpdateAllMirrorsWorker JID-06aeaa3b0aadacf9981f368e: done: 0.139 sec","job_status":"done","duration":0.139,"completed_at":"2018-04-03T22:57:22.071Z"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65616')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_sidekiq_4_error(self) -> None:
        log = '''{"severity":"ERROR","time":"2018-04-03T22:57:22.071Z","queue":"cronjob:update_all_mirrors","args":[],"class":"UpdateAllMirrorsWorker","retry":false,"queue_namespace":"cronjob","jid":"06aeaa3b0aadacf9981f368e","created_at":"2018-04-03T22:57:21.930Z","enqueued_at":"2018-04-03T22:57:21.931Z","pid":10077,"message":"UpdateAllMirrorsWorker JID-06aeaa3b0aadacf9981f368e: done: 0.139 sec","job_status":"done","duration":0.139,"completed_at":"2018-04-03T22:57:22.071Z"}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65617')
        self.assertEqual(response.rule_level, 5)


    def test_gitlab_shell_stderr_1_info_1(self) -> None:
        log = '''I, [2015-02-13T06:17:00.671315 #9291]  INFO -- : Adding project root/example.git at </var/opt/gitlab/git-data/repositories/root/dcdcdcdcd.git>.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-shell-stderr')
        self.assertEqual(response.rule_id, '65618')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_shell_stderr_1_info_2(self) -> None:
        log = '''I, [2015-02-13T06:17:00.679433 #9291]  INFO -- : Moving existing hooks directory and symlinking global hooks directory for /var/opt/gitlab/git-data/repositories/root/example.git.'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-shell-stderr')
        self.assertEqual(response.rule_id, '65618')
        self.assertEqual(response.rule_level, 3)


    def test_gitlab_shell_stderr_2_warn_1(self) -> None:
        log = '''W, [2015-02-13T07:16:01.312916 #9094]  WARN -- : #<Unicorn::HttpServer:0x0000000208f618>: worker (pid: 9094) exceeds memory limit (320626688 bytes > 247066940 bytes)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-shell-stderr')
        self.assertEqual(response.rule_id, '65619')
        self.assertEqual(response.rule_level, 5)


    def test_gitlab_shell_stderr_2_warn_2(self) -> None:
        log = '''W, [2015-02-13T07:16:01.313000 #9094]  WARN -- : Unicorn::WorkerKiller send SIGQUIT (pid: 9094) alive: 3621 sec (trial 1)'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'gitlab-shell-stderr')
        self.assertEqual(response.rule_id, '65619')
        self.assertEqual(response.rule_level, 5)


    def test_gitlab_graphql_query(self) -> None:
        log = '''{"query_string":"query IntrospectionQuery{__schema {queryType { name },mutationType { name }}}...(etc)","variables":{"a":1,"b":2},"complexity":181,"depth":1,"duration":7}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65620')
        self.assertEqual(response.rule_level, 3)


    def test_get_request_completed_succesfully(self) -> None:
        log = '''{"time":"2018-10-29T12:49:42.123Z","severity":"INFO","duration":709.08,"db":14.59,"view":694.49,"status":200,"method":"GET","path":"/api/v4/projects","params":[{"key":"action","value":"git-upload-pack"},{"key":"changes","value":"_any"},{"key":"key_id","value":"secret"},{"key":"secret_token","value":"[FILTERED]"}],"host":"localhost","ip":"::1","ua":"Ruby","route":"/api/:version/projects","user_id":1,"username":"root","queue_duration":100.31,"gitaly_calls":30,"gitaly_duration":5.36}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65621')
        self.assertEqual(response.rule_level, 3)


    def test_error_couldnt_complete_get_request(self) -> None:
        log = '''{"method":"GET","path":"/api/v4/projects","format":"html","controller":"Projects::IssuesController","action":"show","status":400,"duration":229.03,"view":174.07,"db":13.24,"time":"2017-08-08T20:15:54.821Z","params":[{"key":"param_key","value":"param_value"}],"remote_ip":"18.245.0.1","user_id":1,"username":"admin","gitaly_calls":76,"gitaly_duration":7.41,"queue_duration": 112.47}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65622')
        self.assertEqual(response.rule_level, 5)


    def test_redirection_the_get_request_has_more_than_one_possible_response(self) -> None:
        log = '''{"method":"GET","path":"/api/v4/projects","format":"html","controller":"Projects::IssuesController","action":"show","status":300,"duration":229.03,"view":174.07,"db":13.24,"time":"2017-08-08T20:15:54.821Z","params":[{"key":"param_key","value":"param_value"}],"remote_ip":"18.245.0.1","user_id":1,"username":"admin","gitaly_calls":76,"gitaly_duration":7.41,"queue_duration": 112.47}'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'json')
        self.assertEqual(response.rule_id, '65623')
        self.assertEqual(response.rule_level, 5)

