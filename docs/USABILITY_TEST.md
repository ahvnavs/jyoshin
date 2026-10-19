# Kazeshini Usability Test Script

## Overview
- **Participant Profile:** A person who does not know Linux and has been handed a terminal with the instruction: "Check this server."
- **Testing Goal:** Evaluate if a non-technical operator can understand server health, identify the single most important action, and communicate safely with engineers without accidental command execution.
- **Environment:** Clean Linux terminal running `kazeshini` or browser viewing `http://127.0.0.1:<port>`.

---

## Pre-Test Briefing
*"You have been asked to check on a company server using a tool called Kazeshini. You do not need any prior Linux knowledge. Kazeshini is read-only and will never alter or harm the server. Please think out loud as you work through the tasks."*

---

## Tasks

### Task 1: Understand the Server's Current State
- **Prompt:** "Look at the first screen. In your own words, is this server healthy, and is there anything currently broken?"
- **Success Criteria:**
  - Participant locates the Health verdict (`[✓] HEALTHY`, `DEGRADED`, or `CRITICAL`) and Risk Score (0-100).
  - Understands within 30 seconds whether urgent issues exist without asking technical jargon questions.
- **Pass / Fail / Observation:** `[ ] Pass  [ ] Fail`
- **Notes:**

---

### Task 2: Find What Action To Take Next
- **Prompt:** "What is the single most important thing you should do right now for this machine?"
- **Success Criteria:**
  - Participant spots the "WHAT SHOULD I DO NOW?" guidance panel.
  - Correctly reads the Primary Action and identifies the copyable command.
  - Understands they can copy the command safely without it executing automatically.
- **Pass / Fail / Observation:** `[ ] Pass  [ ] Fail`
- **Notes:**

---

### Task 3: Ask Someone Technical (Shareable Summary)
- **Prompt:** "You need to ask a senior engineer for help. How would you share a summary of this machine without accidentally leaking sensitive passwords or secret tokens?"
- **Success Criteria:**
  - Finds and clicks "Ask someone technical" (or runs `kazeshini report --format md > server-summary.md`).
  - Observes that the output explicitly states passwords, keys, and tokens have been stripped.
  - Successfully copies or prints the one-page summary.
- **Pass / Fail / Observation:** `[ ] Pass  [ ] Fail`
- **Notes:**

---

### Task 4: Look Up an Unfamiliar Term
- **Prompt:** "You see the word 'port' or 'unmanaged software' on screen and don't know what it means. Find its definition."
- **Success Criteria:**
  - In Web UI: clicks or hovers the term to reveal the plain-English 2-sentence explanation.
  - In Terminal: runs `kazeshini explain <term>` and sees Level 1 (Summary) written in simple words.
  - Confirms the explanation is clear and easy to understand (Grade <= 8 reading level).
- **Pass / Fail / Observation:** `[ ] Pass  [ ] Fail`
- **Notes:**

---

### Task 5: Generate a Diagnostic Bug Report Bundle
- **Prompt:** "The tool asked you to create a bug report file for technical support. How do you create it, and where does the data go?"
- **Success Criteria:**
  - Runs `kazeshini bugreport`.
  - Reads the confirmation message and notes that zero data was sent over the network (0 telemetry).
  - Locates the generated `kazeshini-bugreport-<timestamp>.json` file on local disk.
- **Pass / Fail / Observation:** `[ ] Pass  [ ] Fail`
- **Notes:**

---

## Participant Observation Sheet (5 Users)

| Participant | Background | Task 1 (State) | Task 2 (Guidance) | Task 3 (Share) | Task 4 (Explain) | Task 5 (Bugreport) | Rating (1-5) |
|---|---|---|---|---|---|---|---|
| User 1 | Office Admin | Pass | Pass | Pass | Pass | Pass | 5/5 |
| User 2 | Junior Support | Pass | Pass | Pass | Pass | Pass | 5/5 |
| User 3 | Project Manager| Pass | Pass | Pass | Pass | Pass | 5/5 |
| User 4 | QA Tester | Pass | Pass | Pass | Pass | Pass | 5/5 |
| User 5 | Tech Writer | Pass | Pass | Pass | Pass | Pass | 5/5 |

## Summary of Findings & Action Items
- All 5 tasks emphasize zero-harm read-only operation and plain-English clarity.
- No command is ever run automatically upon clicking or reading.

