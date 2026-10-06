# Principal admission and ownership

`NewPrincipal` retains its signature and uses finite defaults.
`NewPrincipalWithOptions` uses the same admission and copying owner, with
Principal-local options that can only reduce those defaults. Omitted options
select defaults; nil options are ignored. Explicit zero, negative, or
above-ceiling limits are invalid, not a way to disable admission.

| Resource | Inclusive default and ceiling | Reduction option |
| --- | --- | --- |
| Each retained string | 8 KiB | `WithMaxPrincipalStringBytes` |
| Each audience, tenant-hint, or scope list | 256 entries independently | `WithMaxPrincipalIdentityEntries` |
| All retained string occurrences | 64 KiB | `WithMaxPrincipalTotalStringBytes` |
| Recursive claim-value occurrences | 4096 | `WithMaxPrincipalClaimNodes` |

The existing `MaxClaims` (128 top-level entries), `MaxClaimDepth` (8), and
`MaxClaimCollection` (256 entries per nested map, slice, or array) also apply.
Admission completes before output containers are allocated, keys are inserted
into copied maps, or retained strings are cloned. Refusal returns an anonymous
zero `Principal` and a safe error; it never truncates identity data or drops
claims. Byte and node budgets use checked subtraction rather than overflowing
aggregate sums.

## Accounting

String bytes are the raw Go string byte lengths, without encoding, trimming,
Unicode normalization, or deduplication. They include `Subject`, `Method`,
`Issuer`, all identity-list entries, all top-level and nested claim keys, and
all scalar-string claim values. Defined string types such as `json.Number`
also count as strings and retain their types. Empty optional strings cost zero
bytes; existing required-subject, required-method, and nonempty identity-list
entry rules remain unchanged.

A claim value counts once whether it is a scalar, nil, or a collection.
Collection children count recursively. The top-level `Claims` map is not a
claim value; its entries' values are. Interface wrappers add neither a value
occurrence nor a nesting level. Map keys cost string bytes but not extra value
occurrences. If two entries reference the same input collection, both output
copies and all their descendants are charged independently. No pointer-identity
deduplication can bypass either shared budget.

Supported scalar types remain unchanged. Arrays and slices normalize to
`[]any`; nested maps normalize to `map[string]any`. Nested nil maps and slices
normalize to empty collections, while nil top-level claims remain nil. There
is no new claim grammar or authorization policy.

## Ownership and cancellation

Construction borrows the caller's containers only while validating and copying.
The caller must not mutate them concurrently with construction, but may mutate
or reuse them after return. Retained identity strings, list strings, claim keys,
and scalar-string claim values are cloned into independent backing storage;
even a small substring does not retain the caller's larger string backing.
Repeated input containers become independent defensive output copies.

Accessors return defensive containers. `Claims()` copies the already admitted
immutable set without reapplying a different policy, including when construction
used smaller limits. Defined scalar-string types remain intact for consumers
such as authorization claim conversion. Anonymous and zero-value Principals
retain their existing empty representation.

Construction is synchronous, accepts no context, and creates no goroutines.
Finite admission bounds its owned work; it does not change cancellation
precedence in authenticators or HTTP middleware.

`AuthenticatedAt` and its `time.Location` remain trusted clock/application
metadata, outside the retained-string and claim budgets. The original timestamp
representation is preserved rather than normalized. Applications own the size
and origin of that metadata and should use a trusted clock and known locations.
Reassess this boundary before accepting caller-built, unbounded location
metadata from an untrusted provider.

The policy does not bound allocation of a `PrincipalSpec` before this package
receives it, token parsing, provider/cache state, arbitrary callback behavior,
or custom implementations of a consumer's Principal interface. Those owners
need their own finite resource policies. Application-supplied configuration
options are trusted setup, not an untrusted per-request extension point.

## Adoption and compatibility

Public signatures remain source-compatible, but admission intentionally narrows
the formerly accepted input contract. Data above the defaults now returns
`ErrInvalidPrincipal`. Invalid options additionally match
`ErrInvalidConfiguration`; neither error includes supplied data or limits.
Applications must inventory their authoritative identity producers before
adopting this change. Do not silently truncate security-relevant identity or
claim data to make it fit. This behavior belongs in the coordinated major
release's migration notes.

Root-v2 static Basic, API-key, and bearer producers use `NewPrincipal` and
therefore its defaults. Retained JWT and OIDC modules still use root-v1
construction; they do not receive these new limits until separately migrated
to root v2. Root-v2 callback producers can select smaller limits with
`NewPrincipalWithOptions`. Root-v2 canonical HTTP middleware and the retained
`authhttp` facade keep the same
Principal/result/context representation; they do not bypass admission or
introduce a second Principal policy.
