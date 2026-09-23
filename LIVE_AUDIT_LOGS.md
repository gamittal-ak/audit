# Live audit activity

The audit progress screen shows timestamped terminal-style activity, refreshed
with the existing authenticated status poll every two seconds. It includes audit
stages, group discovery, property completion, traffic batches, origin probes,
API retries and shared-budget waits. New audits emit these events; workers already
running an audit at deployment continue their existing progress reporting.

The panel follows new entries until the reader scrolls up or turns auto-scroll
off. The visible line and keyboard focus survive refreshes. Follow latest resumes
scrolling. Errors retain the activity panel; successful runs open the report.

Activity consists of explicit summaries, never a stream of raw Docker logs, HTTP
responses, credentials, or exception traces. ContextVar scope keeps concurrent
audits separate. Entries are escaped in templates. Redis stores at most 300 lines
per task under task:{id}:activity, expiring 24 hours after the last entry. Report
deletion also removes activity. Activity storage failures do not fail the audit;
writes back off for 30 seconds after a storage error.

Validation: 95 checks passed on September 23, 2026, including real Redis isolation,
retention and shared API limits, a synthetic full pipeline, authentication, HTML
escaping, cleanup, failure handling, and desktop/mobile browser polling. Tests do
not call Akamai APIs. Set TEST_REDIS_URL to enable the Redis integration checks.
