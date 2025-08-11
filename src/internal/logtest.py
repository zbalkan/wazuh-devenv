import json
import logging
import socket
import struct
from enum import Enum, auto
from typing import Any, Final, Optional

# The socket path is a constant since it's determined by Wazuh
LOGTEST_SOCKET: Final[str] = '/var/ossec/queue/sockets/logtest'

# This constant represents the maximum size for a single event in Wazuh.
# It is derived from the OS_MAXSTR definition (OS_SIZE_65536) in the Wazuh source code,
# which defines the size of the buffers used to receive log data from sockets.
WAZUH_MAX_EVENT_SIZE: Final[int] = 65536


class _WazuhLogtestHelpers:

    @staticmethod
    def is_socket_open() -> bool:
        """Check if the socket is open.

        Returns:
            bool: True if the logtest socket is open, False otherwise.
        """

        # Create a TCP/IP socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)  # Set a timeout for the connection attempt

        try:
            # Try to connect to the host and port
            s.connect(LOGTEST_SOCKET)
            return True  # Socket is open
        except (socket.timeout, socket.error):
            return False  # Socket is closed or connection failed
        finally:
            s.close()  # Close the socket

    @staticmethod
    def send(msg: str) -> bytes:
        """Send and receive data to Wazuh socket with message size framing.

        Args:
            msg (str): The message to send.

        Returns:
            bytes: The received response.

        Raises:
            ConnectionError: If communication fails.
        """
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wlogtest_conn:
                wlogtest_conn.connect(LOGTEST_SOCKET)
                encoded_msg = msg.encode('utf-8')
                wlogtest_conn.sendall(struct.pack(
                    "<I", len(encoded_msg)) + encoded_msg)
                # Read the size header
                size_data = wlogtest_conn.recv(4, socket.MSG_WAITALL)
                if not size_data:
                    raise ConnectionError(
                        "No data received from Wazuh socket.")
                size = struct.unpack("<I", size_data)[0]
                # Read the response message
                recv_msg = b''
                while len(recv_msg) < size:
                    chunk = wlogtest_conn.recv(
                        size - len(recv_msg), socket.MSG_WAITALL)
                    if not chunk:
                        break
                    recv_msg += chunk
                return recv_msg
        except socket.error as e:
            raise ConnectionError(
                f"Failed to communicate with Wazuh socket: {e}")

    @staticmethod
    def wrap_command(command: str, parameters: dict) -> str:
        """Wrap data with Wazuh daemon protocol information.

        Args:
            command (str): The command to send.
            parameters (dict): The parameters for the command.

        Returns:
            str: The JSON-formatted message.
        """
        msg: dict[str, Any] = {
            'version': 1,
            'origin': {
                'name': "wazuh-logtest",
                'module': "wazuh-logtest"
            }
        }
        msg['command'] = command
        msg['parameters'] = parameters
        return json.dumps(msg)

    @staticmethod
    def unwrap_response(msg: bytes) -> Any:
        """Unwrap data from Wazuh daemon protocol information.

        Args:
            msg (bytes): The received message in bytes.

        Returns:
            dict: The parsed JSON message.

        Raises:
            ValueError: If the message cannot be decoded.
        """
        try:
            json_msg: Any = json.loads(msg.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to decode JSON response: {e}")
        if json_msg.get('error'):
            error_msg = json_msg.get('message', 'Unknown error')
            error_n = json_msg.get('error')
            raise ValueError(f'{error_n}: {error_msg}')
        return json_msg  # Return the entire message


class _WazuhLogtestSession:
    """Interacts with the wazuh-logtest feature to process logs and manage sessions."""

    def __init__(self, location: str = "stdin", log_format: str = "syslog") -> None:
        self.__fixed_fields: dict[str, str] = {
            'location': location,
            'log_format': log_format
        }
        self.__last_token = ""

    def process_log(self, log: str, token: Optional[str] = None, options: Optional[dict] = None) -> dict:
        """Send a log event to wazuh-logtest and receive the outcome.

        Args:
            log (str): The log message to process.
            token (Optional[str]): The session token to use.
            options (Optional[dict]): Additional options.

        Returns:
            dict: The response from the Wazuh daemon.
        """

        if len(log.encode('utf-8')) > WAZUH_MAX_EVENT_SIZE:
            raise ValueError(f"Log size exceeds the maximum limit of {WAZUH_MAX_EVENT_SIZE} bytes.")

        data: dict[str, Any] = self.__fixed_fields.copy()
        if token:
            data['token'] = token
        # Remove leading and trailing newlines
        data['event'] = log.strip('\n')
        if options:
            data['options'] = options

        request: str = _WazuhLogtestHelpers.wrap_command('log_processing', data)

        logging.debug('Request: %s', request)
        recv_packet = _WazuhLogtestHelpers.send(request)
        logging.debug('Reply: %s', recv_packet.decode('utf-8'))
        # Unwrap the response
        reply: dict = _WazuhLogtestHelpers.unwrap_response(recv_packet)

        # Update the session token
        new_token = reply.get('data', {}).get('token')
        if new_token:
            self.__last_token = new_token
        return reply

    def remove_last_session(self) -> None:
        """Remove the last session to clean up."""
        if self.__last_token:
            self.remove_session(self.__last_token)

    def remove_session(self, token: str) -> bool:
        """Remove session by token.

        Args:
            token (str): The session token to remove.

        Returns:
            bool: True if the session was removed successfully.
        """
        data: dict[str, Any] = self.__fixed_fields.copy()
        data['token'] = token

        request: str = _WazuhLogtestHelpers.wrap_command('remove_session', data)

        try:
            recv_packet = _WazuhLogtestHelpers.send(request)
            reply: dict = _WazuhLogtestHelpers.unwrap_response(recv_packet)
            codemsg = int(reply.get('codemsg', -1))
            return codemsg >= 0
        except Exception as e:
            logging.error(f"Failed to remove session: {e}")
            return False


class LogtestStatus(Enum):
    """
    Represents the result status of a log processed by the Wazuh logtest daemon.

    This enumeration encodes the semantic outcome of log analysis, based on whether a decoder
    was applied, a rule matched, or an error occurred during processing. It enables structured
    branching logic and test assertions based on the analysis result.

    Members:
        RuleMatch: A rule matched the log; indicates successful decoding and rule application.
        Error: An error occurred during processing, such as malformed input or internal failure.
        NoDecoder: No decoder matched the log format; the log could not be interpreted.
        NoRule: A decoder matched, but no rule was triggered.

    Usage:
        Used by LogtestResponse to classify processing outcomes in a reliable, testable way.
    """

    RuleMatch = auto()
    Error = auto()
    NoDecoder = auto()
    NoRule = auto()


class LogtestResponse:
    """
    Represents the structured response returned by Wazuh's logtest daemon after processing a log message.

    This class parses and stores key elements from the daemon response, including alert status, rule matching,
    decoder used, parsed fields, and any associated error. It also determines the processing status based on the
    presence of decoder, rule, and error codes.

    Attributes:
        status (LogtestStatus): The status indicating whether a rule matched, decoder was found, or an error occurred.
        alert (bool): Indicates whether an alert was triggered.
        full_log (str): The original log as reconstructed or normalized by Wazuh.
        timestamp (str): The timestamp associated with the log.
        location (str): The location field indicating the origin of the log.
        decoder (Optional[str]): The name of the decoder applied to the log, if any.
        rule_id (Optional[str]): The ID of the rule matched, if any.
        rule_level (Optional[int]): The severity level of the matched rule.
        rule_description (Optional[str]): A description of the matched rule.
        rule_groups (list[str]): The list of rule groups associated with the matched rule.
        rule_mitre_ids (list[str]): The list of MITRE ATT&CK TTP IDs associated with the matched rule.

    Methods:
        get_data_field(field_path: list[str]) -> Optional[Any]:
            Retrieves nested parsed data using a path of dictionary keys.

    Usage:
        This class is typically instantiated internally by the logtest interface functions
        and used in testing or monitoring pipelines to verify rule coverage and alerting logic.
    """

    status: LogtestStatus
    alert: bool
    full_log: str
    timestamp: str
    location: str
    decoder: Optional[str] = None
    rule_id: Optional[str] = None
    rule_level: Optional[str] = None
    rule_description: Optional[str] = None
    rule_groups: Optional[set[str]] = None
    rule_mitre_ids: Optional[set[str]] = None

    def __init__(self, response_dict: dict) -> None:

        # Get the data field for more info
        __data: dict[str, Any] = response_dict.get('data', {})

        # Messages for debugging, it's better to get before the error
        self.__messages = __data.get('messages', [])

        # Extract error, return early if there's an error
        if (response_dict.get('error', 0) != 0):
            self.status = LogtestStatus.Error
            return

        self.alert = __data.get('alert', False)

        __output: dict = __data.get('output', {})
        self.full_log = __output.get('full_log', '')
        self.timestamp = __output.get('timestamp', '')
        self.location = __output.get('location', '')

        # Other data fields
        self.__data_fields = __output.get('data', {})

        # Decoder information
        __decoder_info: Optional[dict] = __output.get('decoder', None)

        # No decoder, set status and return early
        if (__decoder_info is None):
            self.status = LogtestStatus.NoDecoder
            return

        self.decoder = __decoder_info.get('name', None)

        # Rule information
        __rule_info: Optional[dict] = __output.get('rule', None)

        # No rule, set status and return early
        if (__rule_info is None):
            self.status = LogtestStatus.NoRule
            return

        self.status = LogtestStatus.RuleMatch

        self.rule_id = __rule_info.get('id', None)
        self.rule_level = __rule_info.get('level', None)
        self.rule_description = __rule_info.get('description', None)

        __groups = __rule_info.get('groups', None)
        if (__groups):
            self.rule_groups = set(__groups)

        __mitre = __rule_info.get('mitre')
        if (__mitre):
            __ids = __mitre.get('id', [])
            self.rule_mitre_ids = set(__ids) if not isinstance(__ids, str) else {__ids}

    def get_data_field(self, field_path: list[str]) -> Optional[Any]:
        """Retrieve nested data fields using a list of keys."""
        data = self.__data_fields
        for key in field_path:
            if isinstance(data, dict):
                data = data.get(key)
                if data is None:
                    return None
            else:
                return None
        return data


def send_log(log: str, location: str = "stdin", log_format: str = "syslog", token: Optional[str] = None) -> LogtestResponse:
    """Send a log to Wazuh logtest and get the response.

    Args:
        log (str): The log message to send.
        location (str): The location of the log.
        log_format (str): The format of the log.
        token (Optional[str]): The session token to use.

    Returns:
        LogtestResponse: The response from Wazuh logtest.
    """
    w_logtest = _WazuhLogtestSession(location=location, log_format=log_format)
    options: dict[str, Any] = {}

    try:
        response_dict: dict[str, Any] = w_logtest.process_log(log, token=token, options=options)
        return LogtestResponse(response_dict)
    except Exception as e:
        logging.error('Error processing log: %s', e)
        raise


def send_multiple_logs(logs: list[str], location: str = "stdin", log_format: str = "syslog", options: Optional[dict] = None) -> list[LogtestResponse]:
    """Send multiple logs to Wazuh logtest within the same session.

    Args:
        logs (list[str]): A list of log messages to send.
        location (str): The location of the logs.
        log_format (str): The format of the logs.
        options (Optional[dict]): Additional options.

    Returns:
        list[LogtestResponse]: A list of responses from Wazuh logtest.
    """
    w_logtest = _WazuhLogtestSession(location=location, log_format=log_format)
    if options is None:
        options = {}
    responses = []
    token = None
    try:
        for log in logs:
            response_dict = w_logtest.process_log(log, token=token, options=options)
            # Update the token after the first log
            if token is None:
                token = response_dict.get('data', {}).get('token')
            response = LogtestResponse(response_dict)
            responses.append(response)
        return responses
    except Exception as e:
        logging.error('Error processing logs: %s', e)
        raise
    finally:
        # After all logs are sent, remove the session, whether it succeeds or not.
        if token:
            w_logtest.remove_session(token)
