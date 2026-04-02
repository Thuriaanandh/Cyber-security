from __future__ import annotations

import asyncio
import subprocess
import re
from urllib.parse import urlparse
from typing import Any, Mapping, Optional

from ..mcp.tool_registry import (
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolMetadata,
    ToolType,
    now_utc,
)

from .base import AbstractScannerAdapter


class NmapScannerConfig:
    def __init__(self):
        self.binary_path = "nmap"  # change to full path if needed
        # Keep Nmap bounded so end-to-end scan stays under 5 minutes.
        self.default_timeout_seconds = 90


class NmapScannerAdapter(AbstractScannerAdapter):

    def __init__(self, config: Optional[NmapScannerConfig] = None) -> None:
        self._config = config or NmapScannerConfig()

        self.metadata = ToolMetadata(
            id="nmap",
            name="Nmap",
            type=ToolType.NMAP,
            version="1.0",
            description="Nmap network scanner",
            supported_vulnerability_types=("exposed_services", "network_misconfig"),
            supports_async=True,
            default_timeout_seconds=self._config.default_timeout_seconds,
        )

    async def execute(self, scan_id: str, params: Mapping[str, Any]) -> ToolExecutionResult:

        started_at = now_utc()

        try:
            target = params.get("target")

            if not target:
                raise ValueError("Target is required")

            parsed = urlparse(target)
            host = parsed.hostname if parsed.hostname else target

            cmd = [
                self._config.binary_path,
                "-sV",
                "-T4",
                host
            ]

            print("DEBUG: Running Nmap:", " ".join(cmd))

            # ✅ Safe execution (Windows compatible)
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=self._config.default_timeout_seconds,
            )

            finished_at = now_utc()

            print("DEBUG: Return code:", result.returncode)

            if result.returncode != 0:
                print("NMAP ERROR:", result.stderr)

                return ToolExecutionResult(
                    tool_id=self.metadata.id,
                    scan_id=scan_id,
                    status=ToolExecutionStatus.FAILED,
                    started_at=started_at,
                    finished_at=finished_at,
                    raw_output={"stderr": result.stderr},
                    normalized_output={},
                    error_message="Nmap execution failed",
                )

            output = result.stdout
            print("NMAP SUCCESS (preview):", output[:200])

            # -------------------------------------------------
            # 🔥 PARSING LOGIC (IMPORTANT PART)
            # -------------------------------------------------
            open_ports = []
            issues = []

            for line in output.split("\n"):
                match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
                if match:
                    port = int(match.group(1))
                    service = match.group(2)

                    # basic severity logic
                    if port in [21, 23, 25, 3389]:
                        severity = "high"
                    elif port in [80, 443]:
                        severity = "medium"
                    else:
                        severity = "low"

                    open_ports.append({
                        "port": port,
                        "service": service,
                        "severity": severity
                    })

                    issues.append({
                        "id": f"nmap-{host}-{port}",
                        "type": "open_port",
                        "severity": severity,
                        "location": f"{host}:{port}",
                        "description": f"Port {port}/tcp is open and exposes service '{service}'.",
                        "evidence": {
                            "source_tool": "nmap",
                            "port": port,
                            "protocol": "tcp",
                            "service": service,
                        },
                    })

            # Always include a baseline host fingerprint issue for quick-mode visibility.
            issues.append({
                "id": f"nmap-{host}-fingerprint",
                "type": "host_service_fingerprint",
                "severity": "info",
                "location": host,
                "description": "Nmap service fingerprint and host reachability check completed.",
                "evidence": {
                    "source_tool": "nmap",
                    "open_ports_count": len(open_ports),
                },
            })

            if not issues:
                issues.append({
                    "id": f"nmap-{host}-baseline",
                    "type": "host_reachability",
                    "severity": "info",
                    "location": host,
                    "description": "Nmap completed quick service discovery but did not identify open ports in scanned scope.",
                    "evidence": {
                        "source_tool": "nmap",
                    },
                })

            normalized = {
                "host": host,
                "total_open_ports": len(open_ports),
                "open_ports": open_ports,
                "issues": issues,
            }

            return ToolExecutionResult(
                tool_id=self.metadata.id,
                scan_id=scan_id,
                status=ToolExecutionStatus.SUCCESS,
                started_at=started_at,
                finished_at=finished_at,
                raw_output={"output": output},
                normalized_output=normalized,
            )

        except subprocess.TimeoutExpired as e:
            print("NMAP TIMEOUT:", str(e))

            return ToolExecutionResult(
                tool_id=self.metadata.id,
                scan_id=scan_id,
                status=ToolExecutionStatus.TIMEOUT,
                started_at=started_at,
                finished_at=now_utc(),
                raw_output={},
                normalized_output={},
                error_message=f"Nmap timed out after {self._config.default_timeout_seconds}s",
            )

        except Exception as e:
            print("NMAP EXCEPTION:", str(e))

            return ToolExecutionResult(
                tool_id=self.metadata.id,
                scan_id=scan_id,
                status=ToolExecutionStatus.FAILED,
                started_at=started_at,
                finished_at=now_utc(),
                raw_output={},
                normalized_output={},
                error_message=str(e),
            )