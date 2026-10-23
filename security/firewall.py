"""
Application-Level Security Firewall & Rule Engine
=================================================
IMPORTANT ACADEMIC & ARCHITECTURAL NOTE:
This module implements an APPLICATION-LAYER (Layer 7) Security Firewall / Rule Engine.
It is designed to inspect HTTP authentication traffic, enforce rate limits, detect brute-force
login attacks, and trigger progressive account lockouts.

* It is NOT an Operating System (OS) firewall (e.g., iptables, Windows Defender Firewall).
* It is NOT a Network-Layer firewall (e.g., Cisco, pfSense).
* Instead, it protects application endpoints against automated credential stuffing,
  theft attempts, and high-frequency request flooding at the software runtime level.
"""

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Tuple, Dict, Any, Optional
from flask import request
from models import db, User, LoginLog

class ApplicationFirewall:
    """
    Stateful in-memory rate limiter and rule engine coupled with
    database-backed persistent account lockout policies.
    """

    def __init__(self, max_failed_attempts: int = 3, lockout_minutes: int = 15,
                 rate_window_seconds: int = 60, max_requests_per_window: int = 20):
        self.max_failed_attempts = max_failed_attempts
        self.lockout_minutes = lockout_minutes
        self.rate_window_seconds = rate_window_seconds
        self.max_requests_per_window = max_requests_per_window
        
        # In-memory IP request tracker: ip -> list of unix timestamps
        self.ip_request_history = defaultdict(list)
        
        # In-memory IP blocklist: ip -> unblock_timestamp
        self.blocked_ips = {}

    def get_client_ip(self) -> str:
        """Extract the real client IP address, respecting reverse proxies if configured."""
        if request.headers.get("X-Forwarded-For"):
            # If behind a proxy, take the first client address in the chain
            ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
        elif request.headers.get("X-Real-IP"):
            ip = request.headers.get("X-Real-IP").strip()
        else:
            ip = request.remote_addr or "127.0.0.1"
        return ip

    def check_ip_rate_limit(self, ip: Optional[str] = None) -> Tuple[bool, str]:
        """
        Application-layer rate limiter.
        Prevents DDoS and automated brute force scripts from flooding the login endpoint.
        Returns (is_allowed, reason_message).
        """
        ip = ip or self.get_client_ip()
        current_time = time.time()

        # Check if IP is under temporary cooldown
        if ip in self.blocked_ips:
            cooldown_until = self.blocked_ips[ip]
            if current_time < cooldown_until:
                remaining_sec = int(cooldown_until - current_time)
                return False, f"Firewall Alert: High traffic detected from your IP. Temporary cooldown for {remaining_sec}s."
            else:
                del self.blocked_ips[ip]

        # Clean old timestamps outside the sliding window
        window_start = current_time - self.rate_window_seconds
        self.ip_request_history[ip] = [ts for ts in self.ip_request_history[ip] if ts > window_start]

        # Check if limit exceeded
        if len(self.ip_request_history[ip]) >= self.max_requests_per_window:
            # Block this IP for 2 minutes
            self.blocked_ips[ip] = current_time + 120
            return False, "Firewall Alert: Excessive requests detected. IP temporarily throttled."

        # Record this request
        self.ip_request_history[ip].append(current_time)
        return True, "Request allowed."

    def evaluate_login_attempt(self, user: Optional[User], email: str, is_password_correct: bool,
                               ml_risk_score: float = 0.0) -> Dict[str, Any]:
        """
        Core Rule Engine for Login Authentication:
        1. Checks whether the target account is currently locked.
        2. If password correct: resets failed counter, logs SUCCESS event.
        3. If password incorrect: increments counter, checks for 3-attempt limit.
        4. If 3rd failed attempt reached: triggers account lockout, flags SUSPICIOUS/THEFT,
           and marks event for critical alerting.
        """
        ip = self.get_client_ip()
        user_agent = request.headers.get("User-Agent", "Unknown")[:255]
        
        # Scenario A: Valid credentials supplied (Immediate Unlock & Access)
        if user and is_password_correct:
            # Entering the correct password immediately releases any lockout and clears failure counter
            user.reset_failed_attempts()
            log = LoginLog(
                user_id=user.id,
                email_attempted=email,
                success=True,
                failed_attempt_count=0,
                ip_address=ip,
                user_agent=user_agent,
                risk_score=ml_risk_score,
                status="SUCCESS"
            )
            db.session.add(log)
            db.session.commit()

            return {
                "allowed": True,
                "status": "SUCCESS",
                "message": "Authentication successful.",
                "trigger_alerts": False,
                "remaining_attempts": self.max_failed_attempts,
                "risk_score": ml_risk_score
            }

        # Scenario C: Invalid credentials (user exists OR user does not exist)
        # Note: To prevent account enumeration, we do NOT tell the user if the email was found.
        if user:
            user.failed_attempts += 1
            current_failures = user.failed_attempts
            if current_failures >= self.max_failed_attempts:
                # 3rd Consecutive Failure -> Trigger Alert and flag incident
                user.lock_account(minutes=self.lockout_minutes)
                status = "BLOCKED"
                trigger_alerts = True
                final_risk = max(ml_risk_score, 0.90)
                message = f"SECURITY ALERT: 3 consecutive failed login attempts detected! Security alert sent to your email & WhatsApp. Enter your correct password to securely unlock and sign in."
            else:
                remaining = self.max_failed_attempts - current_failures
                status = "FAILED"
                trigger_alerts = False
                final_risk = ml_risk_score
                message = f"Invalid email or password. Remaining attempts before security alert: {remaining}."

            log = LoginLog(
                user_id=user.id,
                email_attempted=email,
                success=False,
                failed_attempt_count=current_failures,
                ip_address=ip,
                user_agent=user_agent,
                risk_score=final_risk,
                status=status
            )
            db.session.add(log)
            db.session.commit()

            return {
                "allowed": False,
                "status": status,
                "message": message,
                "trigger_alerts": trigger_alerts,
                "remaining_attempts": max(0, self.max_failed_attempts - current_failures),
                "risk_score": final_risk
            }
        else:
            # User does not exist in DB, but we still log attempt for forensics/analytics
            log = LoginLog(
                user_id=None,
                email_attempted=email,
                success=False,
                failed_attempt_count=1,
                ip_address=ip,
                user_agent=user_agent,
                risk_score=max(ml_risk_score, 0.50),
                status="FAILED"
            )
            db.session.add(log)
            db.session.commit()

            return {
                "allowed": False,
                "status": "FAILED",
                "message": "Invalid email or password.",
                "trigger_alerts": False,
                "remaining_attempts": None,
                "risk_score": log.risk_score
            }

# Singleton instance
firewall = ApplicationFirewall()
