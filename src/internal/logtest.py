import json
import logging
import socket
import struct
from enum import Enum, auto
from typing import Any, Final, Optional

# The socket path is a constant since it's determined by Wazuh
LOGTEST_SOCKET: Final[str] = '/var/ossec/queue/sockets/logtest'


class WazuhDaemonProtocol:
    """Handles the wrapping and unwrapping of messages for communication with Wazuh daemons."""

    def __init__(self, version: int = 1, origin_module: str = "wazuh-logtest", module_name: str = "wazuh-logtest"):
        self.protocol: dict[str, Any] = {
            'version': version,
            'origin': {
                'name': origin_module,
                'module': module_name
            }
        }

    def wrap(self, command: str, parameters: dict) -> str:
        """Wrap data with Wazuh daemon protocol information.

        Args:
            command (str): The command to send.
            parameters (dict): The parameters for the command.

        Returns:
            str: The JSON-formatted message.
        """
        msg = self.protocol.copy()
        msg['command'] = command
        msg['parameters'] = parameters
        return json.dumps(msg)

    def unwrap(self, msg: bytes) -> Any:
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


class WazuhSocket:
    """Handles communication with the Wazuh socket (includes message framing)."""

    def __init__(self, file: str) -> None:
        self.__file = file

    def is_socket_open(self) -> bool:
        """Check if the socket is open.

        Returns:
            bool: True if the logtest socket is open, False otherwise.
        """

        # Create a TCP/IP socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)  # Set a timeout for the connection attempt

        try:
            # Try to connect to the host and port
            s.connect(self.__file)
            return True  # Socket is open
        except (socket.timeout, socket.error):
            return False  # Socket is closed or connection failed
        finally:
            s.close()  # Close the socket

    def send(self, msg: str) -> bytes:
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
                wlogtest_conn.connect(self.__file)
                encoded_msg = msg.encode('utf-8')
                wlogtest_conn.sendall(struct.pack("<I", len(encoded_msg)) + encoded_msg)
                # Read the size header
                size_data = wlogtest_conn.recv(4, socket.MSG_WAITALL)
                if not size_data:
                    raise ConnectionError("No data received from Wazuh socket.")
                size = struct.unpack("<I", size_data)[0]
                # Read the response message
                recv_msg = b''
                while len(recv_msg) < size:
                    chunk = wlogtest_conn.recv(size - len(recv_msg), socket.MSG_WAITALL)
                    if not chunk:
                        break
                    recv_msg += chunk
                return recv_msg
        except socket.error as e:
            raise ConnectionError(f"Failed to communicate with Wazuh socket: {e}")


class WazuhLogtest:
    """Interacts with the wazuh-logtest feature to process logs and manage sessions."""

    def __init__(self, location: str = "stdin", log_format: str = "syslog") -> None:
        self.protocol = WazuhDaemonProtocol()
        self.socket = WazuhSocket(LOGTEST_SOCKET)
        self.fixed_fields = {
            'location': location,
            'log_format': log_format
        }
        self.last_token = ""

    def process_log(self, log: str, token: Optional[str] = None, options: Optional[dict] = None) -> dict:
        """Send a log event to wazuh-logtest and receive the outcome.

        Args:
            log (str): The log message to process.
            token (Optional[str]): The session token to use.
            options (Optional[dict]): Additional options.

        Returns:
            dict: The response from the Wazuh daemon.
        """

        data: dict[str, Any] = self.fixed_fields.copy()
        if token:
            data['token'] = token
        # Remove leading and trailing newlines
        data['event'] = self.__remove_newlines(log)
        if options:
            data['options'] = options

        request = self.protocol.wrap('log_processing', data)
        logging.debug('Request: %s', request)
        recv_packet = self.socket.send(request)
        logging.debug('Reply: %s', recv_packet.decode('utf-8'))
        # Unwrap the response
        reply: dict = self.protocol.unwrap(recv_packet)
        # Update the session token
        new_token = reply.get('data', {}).get('token')
        if new_token:
            self.last_token = new_token
        return reply

    def remove_last_session(self) -> None:
        """Remove the last session to clean up."""
        if self.last_token:
            self.remove_session(self.last_token)

    def remove_session(self, token: str) -> bool:
        """Remove session by token.

        Args:
            token (str): The session token to remove.

        Returns:
            bool: True if the session was removed successfully.
        """
        data: dict[str, Any] = self.fixed_fields.copy()
        data['token'] = token
        request = self.protocol.wrap('remove_session', data)
        try:
            recv_packet = self.socket.send(request)
            reply = self.protocol.unwrap(recv_packet)
            codemsg = int(reply.get('codemsg', -1))
            return codemsg >= 0
        except Exception as e:
            logging.error(f"Failed to remove session: {e}")
            return False

    def __remove_newlines(self, log: str) -> str:
        if (log == ""):
            return log
        if (log[0] == '\n'):
            log = log[1:]
        if (log[-1] == '\n'):
            log = log[:-1]
        return log


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
        messages (Any): List or object containing informational or warning messages from Wazuh.
        token (str): The session token used for multi-log sessions.
        alert (bool): Indicates whether an alert was triggered.
        full_log (str): The original log as reconstructed or normalized by Wazuh.
        timestamp (str): The timestamp associated with the log.
        location (str): The location field indicating the origin of the log.
        decoder (Optional[str]): The name of the decoder applied to the log, if any.
        error (Any): The error code returned by the daemon (0 for success).
        rule_id (Optional[str]): The ID of the rule matched, if any.
        rule_level (Optional[int]): The severity level of the matched rule.
        rule_description (Optional[str]): A description of the matched rule.
        rule_groups (list[str]): The list of rule groups associated with the matched rule.

    Methods:
        get_data_field(field_path: list[str]) -> Optional[Any]:
            Retrieves nested parsed data using a path of dictionary keys.

    Usage:
        This class is typically instantiated internally by the logtest interface functions
        and used in testing or monitoring pipelines to verify rule coverage and alerting logic.
    """

    status: LogtestStatus
    messages: Any
    token: str
    alert: bool
    full_log: str
    timestamp: str
    location: str
    decoder: Optional[str]
    error: Any
    rule_id: Optional[str]

    def __init__(self, response_dict: dict) -> None:

        # Extract error and data from the response
        self.error = response_dict.get('error', 0)
        __data = response_dict.get('data', {})

        self.messages = __data.get('messages', [])
        self.token = __data.get('token', '')
        self.alert = __data.get('alert', False)

        __output = __data.get('output', {})
        self.full_log = __output.get('full_log', '')
        self.timestamp = __output.get('timestamp', '')
        self.location = __output.get('location', '')

        # Decoder information
        __decoder_info = __output.get('decoder', {})
        self.decoder = __decoder_info.get('name', None)

        # Rule information
        __rule_info = __output.get('rule', {})
        self.rule_id = __rule_info.get('id', None)
        self.rule_level = __rule_info.get('level', None)
        self.rule_description = __rule_info.get('description', None)
        self.rule_groups = __rule_info.get(
            'groups', []) if 'groups' in __rule_info else []

        # Parsed data
        self.__parsed_data = __output.get('data', {})

        # Determine the status
        self.status = self.__determine_status()

    def __determine_status(self) -> LogtestStatus:
        """Determine the status of the response."""
        if self.error != 0:
            return LogtestStatus.Error
        if not self.decoder:
            return LogtestStatus.NoDecoder
        if not self.rule_id:
            return LogtestStatus.NoRule
        return LogtestStatus.RuleMatch

    def get_data_field(self, field_path: list[str]) -> Optional[Any]:
        """Retrieve nested data fields using a list of keys."""
        data = self.__parsed_data
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
    w_logtest = WazuhLogtest(location=location, log_format=log_format)
    options: dict[str, Any] = {}

    try:
        response_dict = w_logtest.process_log(log, token=token, options=options)
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
    w_logtest = WazuhLogtest(location=location, log_format=log_format)
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
        # After all logs are sent, remove the session
        if token:
            w_logtest.remove_session(token)
        return responses
    except Exception as e:
        logging.error('Error processing logs: %s', e)
        raise
