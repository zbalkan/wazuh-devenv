"""Safe subprocess execution with narrow privilege elevation."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence

from .errors import CommandError
from .paths import InvokingUser


class CommandRunner:
    def __init__(self, user: InvokingUser) -> None:
        self.user = user

    @staticmethod
    def _require(executable: str) -> str:
        resolved = shutil.which(executable)
        if not resolved:
            raise CommandError(f"required command not found: {executable}")
        return resolved

    def command(self, args: Sequence[str], *, privileged: bool = False) -> list[str]:
        if not args:
            raise ValueError("command must not be empty")
        if privileged and os.path.isabs(args[0]):
            executable = args[0]
        else:
            executable = self._require(args[0])
        command = [executable, *args[1:]]
        if privileged and os.geteuid() != 0:
            sudo = self._require("sudo")
            return [sudo, "--", *command]
        return command

    def run(
        self,
        args: Sequence[str],
        *,
        privileged: bool = False,
        check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = self.command(args, privileged=privileged)
        result = subprocess.run(command, check=False, text=True, env=env)
        if check and result.returncode != 0:
            raise CommandError(f"command failed ({result.returncode}): {' '.join(command)}")
        return result

    def capture(self, args: Sequence[str], *, privileged: bool = False) -> str:
        command = self.command(args, privileged=privileged)
        result = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0:
            detail = result.stderr.strip()
            suffix = f": {detail}" if detail else ""
            raise CommandError(f"command failed ({result.returncode}): {' '.join(command)}{suffix}")
        return result.stdout

    def run_as_user(self, args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
        if os.geteuid() != 0 or self.user.uid == 0:
            return self.run(args, check=check)

        sudo = self._require("sudo")
        executable = self._require(args[0])
        command = [sudo, "-u", self.user.name, "-H", "--", executable, *args[1:]]
        result = subprocess.run(command, check=False, text=True)
        if check and result.returncode != 0:
            raise CommandError(f"command failed ({result.returncode}): {' '.join(command)}")
        return result
