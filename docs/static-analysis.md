# Static manifest and configuration analysis

APKTrust runs these checks locally as part of every fresh APK scan, including
individual APK components inside XAPK/APKS containers. No additional API key,
cloud quota or upload is needed. Existing deterministic findings remain separate
from AI interpretation and remote evidence.

## Implemented surface

The rule catalog now has 37 checks: five bounded code/reference signals plus
32 manifest/configuration checks. `/api/v1/rules` supplies the same catalog used
by Rules & detection; the UI no longer maintains an independent eight-rule list.

Checks include SMS/call-log permissions, install-packages, app enumeration,
all-files access, overlays, accessibility services/configuration, notification
listeners, device-admin policies, startup receivers, SMS intent priority,
backup declarations/exclusions, shared UID, secret-code intents, broad URI
patterns, legacy SDK/provider context, test-only builds, before-unlock components,
non-default task configuration, cleartext policy, user trust anchors, explicit
pin overrides and debug trust settings. Four declaration-combination checks link
installer/startup/network, SMS/network, accessibility/overlay/network, and
administrator/startup capabilities. These combinations do not establish runtime
behavior or data flow.

## Exported component assessment

The analyzer resolves explicit/implicit export state, target-SDK provider
defaults, missing Android 12+ exported declarations on filtered components,
disabled components, application-level permission inheritance, activity-alias
target permission inheritance, and provider read/write guards. APK-declared
permissions are classified by protectionLevel, including integer encodings and
flags. A selected platform permission vocabulary is recognized. Unknown external
permission protection remains Unknown; it is not treated as unguarded.

Signature-protected components are not flagged as unguarded. A normal/dangerous
guard gets a separate lower-severity finding. Code-level caller checks, provider
path permissions, URI grants, privileged roles and runtime reachability remain
unverified. Permissions listed in the manifest are not proof of grants or use;
maxSdkVersion and uses-permission-sdk-23 are retained as applicability context.
The sensitive permission count is informational and not a malware score.

## Referenced XML resources

The scanner follows named XML references or compiled resource IDs through a
bounded resources.arsc parser and parses binary/text XML. Resource-shrinker paths
such as res/8G.xml are supported without extracting files. Each evidence item
records the exact archive entry, configuration snippet, analyzer, evidence tier
and scanned APK SHA-256. Bundle evidence additionally records its container
SHA-256 and inner APK path.

Network configuration checks distinguish domain/base policy, cleartext
inheritance, user certificate anchors and debug-only overrides. A declared
network config takes precedence over the manifest cleartext flag. Release builds
do not receive an active debug-trust warning solely for a debug-overrides node.
Backup enablement is informational; actual sensitive-data exposure, OEM transfer
behavior and device-selected resource variants are not proven.

Missing, malformed, unsupported or over-budget references produce explicit gaps
and partial configuration coverage. XML references are limited to 16 variants,
2 MiB per XML, 64 levels and 20,000 elements. The resource table is limited to
8 MiB. All reads share the existing 128 MiB indexing budget. Simple file-valued
resource entries are supported; complex/dynamic aliases are left unresolved.
No APK content is executed and no path is extracted onto the filesystem.

## UI and AI

Manifest shows protection labels, effective export state, inheritance basis,
provider read/write guards and configuration gaps. Findings retain STATIC source
and MANIFEST_CONFIG tier; high confidence concerns the declaration, not malicious
intent. Only meaningful low/medium/high findings influence the review label;
informational context alone leaves the assessment inconclusive.

AI receives known rule IDs, severity, declaration tiers, all static rule counts,
component-guard aggregates and gap counts. Existing bounded per-finding commentary
limits still apply; full rule aggregates include findings beyond that limit.
Raw manifest/resource text, APK bytes, private paths and credentials are not
added to the AI payload. Exported reports contain the ordinary evidence findings.

## Remaining layers from the gap report

This release implements the manifest/configuration foundation. It does not claim
all 53 proposed capabilities are implemented. DEX method bodies, source-to-sink
flows, TLS bypass shapes, scoped API pairs, signing verification, APKiD/YARA,
native hardening and recursive embedded-payload analysis need separate analyzer
adapters and fixtures. Their existing analysis gaps are preserved. Manifest
configuration alone cannot determine whether an APK is safe or malicious.

## Verification

```bash
python3 -m unittest discover -s tests -q
```

Rescan locally after installing this update: previous stored reports are not
silently rewritten or replaced. Restart with `./start.sh`, hard refresh the
browser, then upload a package for a new investigation.

Primary references:
[Android service permission inheritance](https://developer.android.com/guide/topics/manifest/service-element),
[provider export and permission semantics](https://developer.android.com/guide/topics/manifest/provider-element),
[custom permission protection levels](https://developer.android.com/guide/topics/manifest/permission-element),
[network security configuration](https://developer.android.com/privacy-and-security/security-config),
[Android backup behavior](https://developer.android.com/identity/data/autobackup).
