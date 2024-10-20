#!/usr/bin/python3
# -*- coding: utf-8 -*-
import json
import logging
import socket
import struct
from typing import Any, Final, Optional

# The socket path is a constant since it's determined by Wazuh
LOGTEST_SOCKET: Final[str] = '/var/ossec/queue/sockets/logtest'

class WazuhDaemonProtocol:
    """Handles the wrapping and unwrapping of messages for communication with Wazuh daemons."""

    def __init__(self, version: int = 1, origin_module: str = "wazuh-logtest", module_name: str = "wazuh-logtest"):
        self.protocol = {
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

    def unwrap(self, msg: bytes) -> dict:
        """Unwrap data from Wazuh daemon protocol information.

        Args:
            msg (bytes): The received message in bytes.

        Returns:
            dict: The parsed JSON message.

        Raises:
            ValueError: If the message cannot be decoded.
        """
        try:
            json_msg = json.loads(msg.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to decode JSON response: {e}")
        if json_msg.get('error'):
            error_msg = json_msg.get('message', 'Unknown error')
            error_n = json_msg.get('error')
            raise ValueError(f'{error_n}: {error_msg}')
        return json_msg  # Return the entire message

class WazuhSocket:
    """Handles communication with the Wazuh socket (includes message framing)."""

    def __init__(self, file: str):
        self.file = file

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
                wlogtest_conn.connect(self.file)
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

    def __init__(self, location: str = "stdin", log_format: str = "syslog"):
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
        data['event'] = log
        if options:
            data['options'] = options

        request = self.protocol.wrap('log_processing', data)
        logging.debug('Request: %s', request)
        recv_packet = self.socket.send(request)
        logging.debug('Reply: %s', recv_packet.decode('utf-8'))
        # Unwrap the response
        reply = self.protocol.unwrap(recv_packet)
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
            codemsg = reply.get('codemsg', -1)
            return codemsg >= 0
        except Exception as e:
            logging.error(f"Failed to remove session: {e}")
            return False

class LogtestResponse:
    """Represents the response from Wazuh logtest."""

    def __init__(self, response_dict: dict) -> None:
        self.raw_response = response_dict
        # Extract error and data from the response
        self.error = response_dict.get('error', 0)
        self.data = response_dict.get('data', {})
        self.messages = self.data.get('messages', [])
        self.token = self.data.get('token', '')
        self.output = self.data.get('output', {})
        self.alert = self.data.get('alert', False)
        self.decoder = self.output.get('decoder', {}).get('name')
        self.rule = self.output.get('rule', {})
        self.rule_description = self.rule.get('description')
        self.rule_id = self.rule.get('id')
        self.rule_level = self.rule.get('level')
        self.rule_groups = self.rule.get('groups', [])
        self.parsed_data = self.output.get('data', {})

    def get_data_field(self, field_path: list[str]) -> Optional[str]:
        """Retrieve nested data fields using a list of keys.

        Args:
            field_path (list[str]): The path to the desired field.

        Returns:
            Optional[str]: The value of the field, or None if not found.
        """
        data = self.parsed_data
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
    options = {}
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
