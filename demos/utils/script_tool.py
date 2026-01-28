# script_tool.py
import subprocess
import shlex
from typing import List, Dict, Any

from fairlib import Tool, ToolResult

class ScriptTool(Tool):
    """
    Tool that runs a *pre‑approved* script and returns its stdout / stderr.
    """
    name = "run_script"
    description = (
        "Runs a pre‑approved script and returns its stdout and stderr.\n"
        "Arguments:\n"
        "  script_name (str) – Name of the script to run (must be in the allowed list).\n"
        "  args (List[str]) – Optional list of command‑line arguments.\n"
    )

    def __init__(self, script_map: Dict[str, str]):
        """
        :param script_map: mapping of user‑friendly script names -> absolute file paths
        """
        self.script_map = script_map
        super().__init__()

    def _run(self, command: List[str], timeout: int = 60) -> Dict[str, Any]:
        """
        Execute command and capture stdout/stderr.
        """
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                shell=False,           # no shell injection
                check=False            # we want to capture non‑zero exits
            )
            return {
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired as exc:
            return {"stdout": "", "stderr": f"Timed out after {timeout}s", "returncode": -1}
        except Exception as exc:      # pragma: no cover
            return {"stdout": "", "stderr": str(exc), "returncode": -1}

    def _run_script(self, script_name: str, args: List[str]) -> ToolResult:
        if script_name not in self.script_map:
            return ToolResult(
                status="error",
                output=f"Script '{script_name}' is not in the approved list."
            )

        path = self.script_map[script_name]
        command = [path] + args
        # Use shlex to escape any tricky characters in the script path itself
        command = [shlex.quote(c) for c in command]
        result = self._run(command)

        return ToolResult(
            status="success",
            output=(
                f"**Script**: `{script_name}`\n"
                f"**Return code**: {result['returncode']}\n\n"
                f"--- stdout ---\n{result['stdout']}\n\n"
                f"--- stderr ---\n{result['stderr']}\n"
            )
        )

    # -------------------------------------------------------------
    # The public interface expected by ToolExecutor
    # -------------------------------------------------------------
    def invoke(self, arguments: dict) -> ToolResult:
        """
        Expected JSON payload:
        {
            "script_name": "list_processes",
            "args": ["-l"]
        }
        """
        script_name = arguments.get("script_name")
        args = arguments.get("args", [])
        if not isinstance(args, list):
            args = [args]          # allow a single string

        return self._run_script(script_name, args)
