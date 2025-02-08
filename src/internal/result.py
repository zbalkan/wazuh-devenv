import json
import unittest
from typing import Literal


class ResultRunTests:

    def __init__(self, test_result: unittest.TestResult) -> None:
        self.test_result: unittest.TestResult = test_result

    @property
    def is_success(self) -> bool:
        return not bool(self.test_result.failures)

    @property
    def status(self) -> Literal['OK'] | Literal['FAILED']:
        return 'OK' if self.is_success else 'FAILED'

    @property
    def verbose_result(self) -> str:
        text_chunks: list = [self.__str__()]

        if len(self.test_result.failures) > 0 or len(self.test_result.errors) > 0:
            text_chunks.append("Test details:")
            for failed_test, traceback in self.test_result.failures:
                text_chunks.append(f"Failure in {failed_test}:\n"
                                   f"{traceback}"
                                   )

            for errored_test, traceback in self.test_result.errors:
                text_chunks.append(f"Error in {errored_test}:\n"
                                   f"{traceback}"
                                   )

        return '\n'.join(text_chunks)

    @property
    def json_result(self) -> str:
        """Retrieve test results in JSON format."""
        successful_tests = self.test_result.testsRun - \
            len(self.test_result.failures) - len(self.test_result.errors)

        res = {
            "test_result": {
                "status": self.status,
                "ran": self.test_result.testsRun,
                "successful": successful_tests,
                "failed": len(self.test_result.failures),
                "errored": len(self.test_result.errors),
                "failures": [str(failed_test) for failed_test, _ in self.test_result.failures] if self.test_result.failures else [],
                "errors": [{'err': str(errored_test), 'traceback': traceback} for errored_test, traceback in self.test_result.errors] if self.test_result.errors else []
            }
        }

        return json.dumps(res)

    def __str__(self) -> str:
        return f"Status: {self.status}\n" \
               f"Ran: {self.test_result.testsRun}\n" \
               f"Failures: {len(self.test_result.failures)}\n" \
               f"Errors: {len(self.test_result.errors)}\n"
