# Edge TLS classification

Audits (report schema version 3) classify every active property separately for
production and staging. Draft versions are not part of the TLS inventory.

## Sources

| Evidence | API | Used for |
|---|---|---|
| Edge hostname `securityType` | HAPI account inventory | sTLS (STANDARD-TLS) vs eTLS (ENHANCED-TLS) network |
| `certProvisioningType`, `certStatus` | PAPI property hostnames (bucket properties via paginated active hostnames) | Certificate type (CPS managed, Default DV, ...) and per-network status |
| Enrollments and deployments | CPS, every contract visible in PAPI groups | Deployed certificate names; HTTP-only evidence |

HAPI and CPS requests have their own rate budgets (HAPI at the PAPI rate, CPS at
28/minute) under the shared global cap; see `RATE_LIMITS.md`. The HAPI inventory is
fetched once per audit; CPS enrollments and deployments are fetched once per audit
before properties are analysed.

## Rules

- A hostname suffix never decides the TLS network; legacy sTLS can use `edgekey.net`.
- Akamai shared certificate: PAPI hostname `cnameType` is `SHARED_CERT`
  (Property Manager shows "Shared"). The hostname pattern alone never decides it.
- A TLS network is not proof of a deployed certificate.
- HTTP-only (client to edge) comes from one of two sources:
  - **Property Manager configuration:** a single-label `*.akamaized.net` property
    hostname equal to its edge hostname, `CPS_MANAGED`, with a reported `cnameType`
    other than `SHARED_CERT` (`CUSTOM` or `EDGE_HOSTNAME`). Property Manager shows
    these as "No certificate (HTTP Only)"; the report labels the certificate type
    "No certificate". Clients that still use HTTPS receive Akamai's
    `*.akamaized.net` wildcard from the edge, so this describes configuration, not
    whether a TLS handshake succeeds.
  - **CPS inventory:** a complete accessible CPS inventory, a custom hostname on
    sTLS, `CPS_MANAGED` provisioning, and no matching deployed certificate or
    pending enrollment on any network.
  Default DV, shared, eTLS, wildcard or other Akamai-domain hostnames, ambiguous
  matches, partial inventories and hostnames whose `cnameType` was not reported are
  never classified HTTP-only.
- `cnameType=EDGE_HOSTNAME` alone means nothing about certificates; most hostnames
  with real CPS or Default DV certificates also report it.
- Reports saved before this rule used the hostname pattern for "Akamai shared".
  They are corrected on display and in Excel downloads from the saved raw PAPI
  records; the saved files are not changed and no rerun is needed.
- Verified against Property Manager on Fox Entertainment (2026-09-24):
  `qa-foxvideo-weather` (`SHARED_CERT`) shows Shared; `foxvideo-sports` (`CUSTOM`)
  and `qa-foxvideo-sports` (`EDGE_HOSTNAME`) show "No certificate (HTTP Only)".
- Failed collections produce Unknown/unavailable rows; properties are never
  dropped. Inactive networks are shown as inactive, not Unknown.

## Known limits

- CPS returns `400 Invalid Contract` for contracts outside the API client's access
  control group. Those contracts make the inventory partial
  (`edge_certificate_coverage.inaccessible_contracts`), so the account gets no
  HTTP-only classifications. Live DIRECTV check (2026-09-24): 4 of 11 contracts
  inaccessible, 23 enrollments, 44 deployment records, inventory partial.
- Certificates outside the API client's visibility are never ruled out.
- Reports saved before schema 3 show TLS as Unknown; rerun the audit to collect it.

## Excel

Original sheets (Summary, All Data, origin sheets) are unchanged except for an
appended Edge TLS summary block. New sheets: `Edge TLS` (property x network),
`Edge Hostnames` (property x hostname x network), `Finding Pivot Source`, and
native refreshable PivotTables `Pivot - TLS`, `Pivot - Certificates`,
`Pivot - Origin Findings`. Verified in desktop Excel: opens without repair,
refresh succeeds, network filter totals are correct.
