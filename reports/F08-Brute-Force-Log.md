RCYC Flag F08 – Brute Force Log Walkthrough
Objective

This report demonstrates how to analyze network authentication logs to identify indicators of a brute-force attack. The methodology is intended for educational purposes and aligns with standard blue-team incident response procedures.

Scenario

The provided authentication log contains multiple login attempts originating from various IP addresses. The objective is to determine which host is responsible for the attack.

Step 1 – Examine Authentication Events

Important fields include:

Timestamp
Source IP
Username
Login Result (Success/Failure)
Protocol

Example:

2026-04-02 08:14:21 Failed login admin from 192.168.10.25
2026-04-02 08:14:22 Failed login admin from 192.168.10.25
2026-04-02 08:14:23 Failed login admin from 192.168.10.25

Multiple failures within seconds indicate automated activity.

Step 2 – Count Failed Logins

Group events by source IP.

Example:

Source IP	Failed Attempts
192.168.10.25	247
192.168.10.31	3
192.168.10.42	2

One IP overwhelmingly exceeds the others.

Step 3 – Look for a Successful Login

Many brute-force attacks conclude with one successful authentication.

Example:

08:15:10 Successful login admin from 192.168.10.25

This confirms the attacker's credentials were eventually accepted.

Step 4 – Build the Timeline
Time	Event
08:14:21	First failed login
08:14:22–08:15:09	Hundreds of failures
08:15:10	Successful authentication

The compressed timeline is characteristic of an automated password guessing attack.

Findings

Evidence indicates that:

One source IP generated an abnormally high number of failed authentication attempts.
The attempts occurred in rapid succession.
The same IP eventually authenticated successfully.

These indicators strongly suggest a brute-force attack.
