from __future__ import annotations

import asyncio
import time
import requests
from typing import Any, Mapping, Optional

from ..mcp.tool_registry import (
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolMetadata,
    ToolType,
    now_utc,
)

from .base import AbstractScannerAdapter


class ZAPScannerConfig:
    def __init__(self):
        self.base_url = "http://localhost:8090"
        self.api_key = None
        # Deeper scan profile with a hard cap.
        self.default_timeout_seconds = 240
        self.enable_active_scan = True


class ZAPScannerAdapter(AbstractScannerAdapter):

    def __init__(self, config: Optional[ZAPScannerConfig] = None) -> None:
        self._config = config or ZAPScannerConfig()

        self.metadata = ToolMetadata(
            id="zap",
            name="OWASP ZAP",
            type=ToolType.ZAP,
            version="1.0",
            description="ZAP web scanner",
            supported_vulnerability_types=("xss", "sqli", "headers"),
            supports_async=True,
            default_timeout_seconds=self._config.default_timeout_seconds,
        )

    async def execute(self, scan_id: str, params: Mapping[str, Any]) -> ToolExecutionResult:

        started_at = now_utc()

        try:
            target = params.get("target")

            if not target:
                raise ValueError("Target required")

            print("DEBUG: Starting ZAP scan")

            # ----------------------------
            # 1. Start spider
            # ----------------------------
            spider_url = f"{self._config.base_url}/JSON/spider/action/scan/"
            spider = requests.get(spider_url, params={"url": target})

            scan_id_zap = spider.json().get("scan")

            # wait for spider with timeout
            print(f"DEBUG: Spider scan started with ID {scan_id_zap}")
            spider_start = time.time()
            while True:
                elapsed = time.time() - spider_start
                if elapsed > self._config.default_timeout_seconds:
                    raise TimeoutError(f"ZAP spider scan exceeded {self._config.default_timeout_seconds}s timeout")

                try:
                    status = requests.get(
                        f"{self._config.base_url}/JSON/spider/view/status/",
                        params={"scanId": scan_id_zap},
                        timeout=10
                    ).json()["status"]
                    status_int = int(status)
                    print(f"DEBUG: Spider status at {elapsed:.1f}s: {status_int}%")
                    
                    if status_int >= 100:
                        print(f"DEBUG: Spider scan completed in {elapsed:.1f}s")
                        break
                except Exception as e:
                    print(f"DEBUG: Spider status check error: {e}")
                    raise

                await asyncio.sleep(2)

            # ----------------------------
            # 2. Active scan
            # ----------------------------
            if self._config.enable_active_scan:
                active_url = f"{self._config.base_url}/JSON/ascan/action/scan/"
                active = requests.get(active_url, params={"url": target})
                active_payload = active.json()
                active_id = active_payload.get("scan")

                # Some targets may not produce a valid active-scan id (e.g. no eligible URLs).
                if active_id is None:
                    print(f"DEBUG: Active scan skipped, response: {active_payload}")
                else:
                    # wait for active scan with timeout
                    print(f"DEBUG: Active scan started with ID {active_id}")
                    active_start = time.time()
                    while True:
                        elapsed = time.time() - active_start
                        if elapsed > self._config.default_timeout_seconds:
                            raise TimeoutError(f"ZAP active scan exceeded {self._config.default_timeout_seconds}s timeout")

                        try:
                            status_payload = requests.get(
                                f"{self._config.base_url}/JSON/ascan/view/status/",
                                params={"scanId": active_id},
                                timeout=10
                            ).json()
                            status = status_payload.get("status")

                            if status is None:
                                raise ValueError(f"Missing active scan status in response: {status_payload}")

                            status_int = int(status)
                            print(f"DEBUG: Active scan status at {elapsed:.1f}s: {status_int}%")

                            if status_int >= 100:
                                print(f"DEBUG: Active scan completed in {elapsed:.1f}s")
                                break
                        except Exception as e:
                            print(f"DEBUG: Active scan status check error: {e}")
                            raise

                        await asyncio.sleep(5)
            else:
                print("DEBUG: Active scan disabled for quick mode")

            # ----------------------------
            # 3. Fetch alerts
            # ----------------------------
            alerts = requests.get(
                f"{self._config.base_url}/JSON/core/view/alerts/",
                params={"baseurl": target}
            ).json()["alerts"]

            issues = []

            for alert in alerts:
                risk_raw = str(alert.get("risk", "")).lower()
                severity = "medium"
                if "high" in risk_raw:
                    severity = "high"
                elif "low" in risk_raw:
                    severity = "low"
                elif "info" in risk_raw:
                    severity = "info"

                issues.append({
                    "id": f"zap-{scan_id}-{len(issues)}",
                    "type": str(alert.get("name") or "web_vuln").strip().lower().replace(" ", "_"),
                    "severity": severity,
                    "location": alert.get("url"),
                    "description": alert.get("description"),
                    "evidence": {
                        "source_tool": "zap",
                        "risk": alert.get("risk"),
                        "param": alert.get("param"),
                        "method": alert.get("method"),
                    },
                })

            if not issues:
                issues.append({
                    "id": f"zap-{scan_id}-baseline",
                    "type": "zap_baseline_scan",
                    "severity": "info",
                    "location": target,
                    "description": "ZAP spider/baseline scan completed with no immediate high-confidence alerts in quick mode.",
                    "evidence": {
                        "source_tool": "zap",
                        "alerts_count": len(alerts),
                        "active_scan_enabled": self._config.enable_active_scan,
                    },
                })

            finished_at = now_utc()

            return ToolExecutionResult(
                tool_id=self.metadata.id,
                scan_id=scan_id,
                status=ToolExecutionStatus.SUCCESS,
                started_at=started_at,
                finished_at=finished_at,
                raw_output={"alerts": alerts[:10]},
                normalized_output={
                    "target": target,
                    "issues": issues,
                    "total_issues": len(issues)
                },
            )

        except Exception as e:
            print("ZAP ERROR:", str(e))

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