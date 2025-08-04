#!/usr/bin/env python3


# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import unittest

from internal.logtest import LogtestStatus, send_log


# Converted from oscap.ini
class TestOscapRules(unittest.TestCase):

    def test_openscap_evaluation_started(self) -> None:
        log = r'''
Apr 12 10:50:32 centos oscap: Evaluation started. Content: /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml, Profile: xccdf_org.ssgproject.content_profile_standard.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81401')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_evaluation_finished(self) -> None:
        log = r'''
Apr 12 10:50:42 centos oscap: Evaluation finished. Return code: 0, Base score 100.000000.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81402')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_evaluation_finished_with_some_failures(self) -> None:
        log = r'''
Apr 12 10:50:42 centos oscap: Evaluation finished. Return code: 2, Base score 100.000000.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81403')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_error_openscap_not_installed(self) -> None:
        log = r'''
oscap: ERROR: OpenSCAP not installed. Details: [Errno 2] No such file or directory
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81502')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_error_impossible_to_execute_openscap(self) -> None:
        log = r'''
oscap: ERROR: Impossible to execute OpenSCAP...
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81503')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_error_wrong_configuration_inexistent_policy(self) -> None:
        log = r'''
oscap: ERROR: File "checklists/ssg-centos7dfa-axccdf.xml" does not exist.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81504')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_error_wrong_configuration_invalid_policy(self) -> None:
        log = r'''
oscap: ERROR: Parsing file "a.xml". Details: "a.xml:1: parser error : Start tag expected, '<' not found".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81505')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_error_problem_executing_oscap(self) -> None:
        log = r'''
oscap: ERROR: Executing profile "standard" of file "checklists/ssg-centos7-xccdf.xml": Return Code: "101" Error: "No such module: eva".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81506')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_error_wrong_configuration_inexistent_profile(self) -> None:
        log = r'''
oscap: ERROR: Profile "kk" does not exist at "checklists/ssg-centos7-xccdf.xml".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81507')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_error_timeout_expired(self) -> None:
        log = r'''
oscap: ERROR: Timeout expired.
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81508')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_rule_pass(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "pass", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81521')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_rule_notchecked(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "notchecked", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81522')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_rule_notapplicable(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "notapplicable", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81523')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_rule_fixed(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fixed", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81524')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_rule_informational(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "informational", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81525')
        self.assertEqual(response.rule_level, 1)


    def test_openscap_rule_error(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "error", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81526')
        self.assertEqual(response.rule_level, 3)


    def test_openscap_rule_unknown(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "unknown", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81527')
        self.assertEqual(response.rule_level, 3)


    def test_openscap_rule_notselected(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "notselected", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81528')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_rule_failed_severity_low(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fail", severity: "low", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81529')
        self.assertEqual(response.rule_level, 5)


    def test_openscap_rule_failed_severity_medium(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fail", severity: "medium", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81530')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_rule_failed_severity_high(self) -> None:
        log = r'''
oscap: msg: "xccdf-result", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", title: "Ensure /tmp Located On Separate Partition", id: "xccdf_org.ssgproject.content_rule_partition_for_tmp", result: "fail", severity: "high", description: "The /tmp directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.", rationale: "The /tmp partition is used as temporary storage by many programs. Placing /tmp in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it." references: "SC-32 (http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf), Test attestation on 20120928 by MM (https://github.com/OpenSCAP/scap-security-guide/wiki/Contributors)", identifiers: "CCE-27173-4 (http://cce.mitre.org)", oval-id: "oval:ssg:def:522", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_rht-ccp", profile-title: "CentOS Profile for Cloud Providers (CPCP)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81531')
        self.assertEqual(response.rule_level, 9)


    def test_openscap_report_overview(self) -> None:
        log = r'''
oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "100.000000".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81540')
        self.assertEqual(response.rule_level, 3)


    def test_openscap_report_overview_score_less_than_90(self) -> None:
        log = r'''
oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "85.835060".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81541')
        self.assertEqual(response.rule_level, 4)


    def test_openscap_report_overview_score_less_than_80(self) -> None:
        log = r'''
oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "75.835060".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81542')
        self.assertEqual(response.rule_level, 5)


    def test_openscap_report_overview_score_less_than_50(self) -> None:
        log = r'''
oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "45.835060".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81543')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_report_overview_score_less_than_30(self) -> None:
        log = r'''
oscap: msg: "xccdf-overview", scan-id: "0011477050403", content: "ssg-centos-7-ds.xml", benchmark-id: "xccdf_org.ssgproject.content_benchmark_RHEL-7", profile-id: "xccdf_org.ssgproject.content_profile_common", profile-title: "Common Profile for General-Purpose Systems", score: "25.835060".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81544')
        self.assertEqual(response.rule_level, 9)


    def test_openscap_oval_pass(self) -> None:
        log = r'''
oscap: msg: "oval-result", scan-id: "0011477050403", content: "cve-ubuntu-xenial-oval.xml", title: "CVE-2002-2439 on Ubuntu 16.04 LTS (xenial) - low.", id: "oval:com.ubuntu.xenial:def:20022439000", result: "pass", description: "operator new[] sometimes returns pointers to heap blocks which are too small. When a new array is allocated, the C++ run-time has to calculate its size. The product may exceed the maximum value which can be stored in a machine register. This error is ignored, and the truncated value is used for the heap allocation. This may lead to heap overflows and therefore security bugs. (See http://cert.uni-stuttgart.de/advisories/calloc.php for further references.)", profile-title: "vulnerability", reference: "CVE-2002-2439 (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81551')
        self.assertEqual(response.rule_level, 0)


    def test_openscap_oval_fail(self) -> None:
        log = r'''
oscap: msg: "oval-result", scan-id: "0011477050403", content: "cve-ubuntu-xenial-oval.xml", title: "CVE-2002-2439 on Ubuntu 16.04 LTS (xenial) - low.", id: "oval:com.ubuntu.xenial:def:20022439000", result: "fail", description: "operator new[] sometimes returns pointers to heap blocks which are too small. When a new array is allocated, the C++ run-time has to calculate its size. The product may exceed the maximum value which can be stored in a machine register. This error is ignored, and the truncated value is used for the heap allocation. This may lead to heap overflows and therefore security bugs. (See http://cert.uni-stuttgart.de/advisories/calloc.php for further references.)", profile-title: "patch", reference: "CVE-2002-2439 (https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439)".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81552')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_oval_report_overview(self) -> None:
        log = r'''
oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "95.19".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81560')
        self.assertEqual(response.rule_level, 3)


    def test_openscap_oval_report_overview_score_less_than_90(self) -> None:
        log = r'''
oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "85.19".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81561')
        self.assertEqual(response.rule_level, 4)


    def test_openscap_oval_report_overview_score_less_than_80(self) -> None:
        log = r'''
oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "75.19".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81562')
        self.assertEqual(response.rule_level, 5)


    def test_openscap_oval_report_overview_score_less_than_50(self) -> None:
        log = r'''
oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "45.19".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81563')
        self.assertEqual(response.rule_level, 7)


    def test_openscap_oval_report_overview_score_less_than_30(self) -> None:
        log = r'''
oscap: msg: "oval-overview", scan-id: "0011477050403", content: "com.ubuntu.xenial.cve.oval.xml", score: "25.19".
'''
        response = send_log(log)

        self.assertEqual(response.status, LogtestStatus.RuleMatch)

        self.assertEqual(response.decoder, 'oscap')
        self.assertEqual(response.rule_id, '81564')
        self.assertEqual(response.rule_level, 9)

