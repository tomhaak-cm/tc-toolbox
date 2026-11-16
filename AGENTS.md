# tc toolbox

Keep the plugin manifest and the skills in this repository as the source of truth.
Treat installed plugin directories as copies.

Read `skills/fix-cve/README.md` before you change the CVE workflow.
Keep the script in `skills/fix-cve/scripts/fix_cve.py` free of third-party Python dependencies.
Keep dependency decisions in the skill and deterministic operations in the script.
Require explicit approval for major upgrades and dependency overrides.
Keep Jira data, credentials, and run state outside Git.

Use the standard-library tests in `tests/`.
Use mock API responses instead of live Jira or GitHub writes in tests.
