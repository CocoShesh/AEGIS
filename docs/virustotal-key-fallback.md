# VirusTotal credential fallback

Put authorized keys in the local `.env` beside `server.py`:

```dotenv
VT_API_KEY=first_key
VT_API_KEY_2=second_key
VT_API_KEY_3=third_key
```

Existing single-key configuration remains supported. Empty entries are ignored;
duplicate keys are deduplicated. Environment variables override the matching
`.env` entries. Keys are read locally, excluded from provider status, and never
stored in scan reports or the database. Restart the server once after installing
this code; later key edits are picked up without a server restart.

The first configured key is preferred until HTTP 429 (rate/quota limit) or HTTP
401 (authentication rejection). A bounded attempt then uses another configured
key. Subsequent requests prefer the successful key. This applies to hash lookups,
extended metadata, uploads and analysis polling. HTTP 403 and 404 do not trigger
rotation: another key should not hide missing reports or access restrictions.

VT requests are serialized across APKTrust workers. Rate-limited keys respect
`Retry-After`, including an HTTP date; without that header they back off for 15
minutes. That cooldown is a retry policy, not an inferred daily/monthly quota
reset. Rejected credentials are disabled for this server process; correcting the
key or restarting permits a new attempt. State is held in process memory.
Provider status displays only numbered slots and AVAILABLE, COOLDOWN or
AUTH_REJECTED. AVAILABLE means eligible for an attempt, not a verified remaining
quota. Account/group quota totals remain UNKNOWN unless separately verified.

When all keys are unavailable, no further requests occur during their cooldown.
The investigation records a reputation gap and continues with static/runtime
and available AI evidence. It never treats missing reputation as a safe result.
Do not assume three keys provide three independent quotas. VT group quotas may
be shared; use only credentials and allowances authorized by your VT account or
license. APKTrust does not hardcode a 500/day or 1,500/day entitlement.

APK upload still requires explicit per-file consent. A successful upload saves
its analysis ID before polling. Polling can switch keys without another upload.
Only an explicit HTTP 401/429 rejection can retry a file with another key. Network
failures, timeouts, malformed success responses and other ambiguous upload
outcomes do not trigger an automatic repeat submission. Large-file upload URL
retrieval and the upload itself use the same selected credential.

Unit tests use mock keys and responses and consume no real provider quota.

References: [quota limits and HTTP 429](https://docs.virustotal.com/docs/consumption-quotas-handled),
[shared group consumption](https://docs.virustotal.com/docs/quota-consumption).
