# Frequently Asked Questions (FAQ)

---

### Does Kazeshini require root?
No. Kazeshini starts and runs as any normal unprivileged user. If run without root, Kazeshini honestly reports what is hidden by Linux permissions and suspends the "Healthy" verdict so operators are not misled.

---

### Does Kazeshini change any settings or restart my services?
No. Kazeshini is strictly read-only. It cannot apply fixes, edit files, or restart daemons. Any remediation must be executed by an authorized human operator.

---

### How much CPU and memory does Kazeshini consume?
Kazeshini is configured with low scheduling priority (`nice 19`, `ionice idle`). Bounded collections take milliseconds, and resident memory typically stays under 30 MB.

---

### Can Kazeshini check servers behind corporate firewalls with no internet access?
Yes. Kazeshini has zero network egress requirements. It does not phone home, does not download external scripts, and embeds its web dashboard and datasets directly into the static binary.

