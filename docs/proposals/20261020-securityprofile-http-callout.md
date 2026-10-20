---
title: Named HTTP Callouts for SecurityProfile
authors:
  - "@Kuromesi"
reviewers: []
creation-date: 2026-10-20
last-updated: 2026-10-20
status: provisional
see-also:
  - "/docs/proposals/20260521-traffic-policy-and-security-profile.md"
  - "https://github.com/openkruise/agents/pull/882"
  - "https://github.com/openkruise/agentio/pull/93"
---

# Named HTTP Callouts for SecurityProfile

## Summary

Add `actions.httpCallout` to `SecurityProfile` and `GlobalSecurityProfile` so
matching rules can delegate request or response processing to a named HTTP
provider. The provider can return mutations or an immediate response. Policy
authors choose the phases, disclosed headers and bodies, and failure behavior;
operators manage provider connections separately in Agentio's EPEConfig.

This proposal describes the API contract introduced by
[agents PR #882](https://github.com/openkruise/agents/pull/882). Installing the
CRD field alone does not enable callout execution. Agentio must consume the
published API, convert the action, and register it in the production filter
pipeline before profiles using the action can enforce policy.

## Motivation

Content scanning and organization-specific request checks need information from
HTTP traffic and must be able to affect its outcome. An asynchronous audit
webhook cannot implement these checks because it does not change the response.
Embedding a provider URL and connection settings in every rule would duplicate
operator configuration and couple policy updates to endpoint or TLS changes.

A named provider separates the connection lifecycle from the policy's decision
about which traffic and data to send.

### Goals

- Support request-only, response-only, and combined callouts in both profile kinds.
- Reuse an operator-managed provider without exposing connection settings in rules.
- Make header and body disclosure explicit, with metadata-only calls by default.
- Define bounded, complete-body disclosure and predictable execution failures.
- Preserve existing rule ordering and released actions.

### Non-Goals/Future Work

- Implementing Agentio conversion or production filter registration in this PR.
- Defining a new Kubernetes provider CRD or namespace-scoped provider lookup.
- Changing credential-provider references or the audit webhook API.
- Streaming or chunked body processing, binary bodies, or truncated inspection.
- Specifying a new wire protocol, retry policy, or Envoy buffering configuration.
  The provider's HTTP Invocation/Decision protocol belongs to Agentio.

## Proposal

### User Stories

1. A platform operator registers a content scanner once and updates its endpoint,
   timeout, or TLS configuration independently of the profiles using it.
2. A policy author sends a request body and selected headers to that scanner,
   blocking traffic if inspection cannot complete.
3. A policy author inspects an upstream response without also disclosing the
   original request headers or body.

### API and Example

Both profile kinds share `SecurityProfileSpec` and `SecurityRuleActions`. The
new optional `httpCallout` field uses `HTTPCalloutAction`; existing selectors,
matching rules, and profile priorities retain their semantics.

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: inspect-model-traffic
  namespace: default
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
    - name: inspect-content
      match:
        - domains: [api.example.com]
      actions:
        httpCallout:
          provider:
            name: content-scanner
          request:
            headers:
              mode: AllowList
              allowList: [content-type, x-request-id]
            body: true
          response:
            headers:
              mode: AllowList
              allowList: [content-type]
            body: true
          maxBodyBytes: 1048576
          failStrategy: Block
```

The example requires a corresponding HTTP callout provider named
`content-scanner` in the serving EPE configuration. For a
`GlobalSecurityProfile`, use that kind and omit `metadata.namespace`; the action
shape is identical.

### Provider Reference and Ownership

`provider` is a required `ExtensionProviderRef` containing only `name`. The name
has no default, is 1–253 characters, and is validated by the API's lowercase DNS
subdomain pattern. There is no `kind` or `namespace` field. The consuming action
determines the required provider type: `httpCallout` requires an HTTP callout
provider in the serving EPE's registry.

The operator owns the provider URL, timeout, and TLS settings. Decision-response
size limits also belong to the provider/runtime side, not to the profile's
`maxBodyBytes`. In the companion
[Agentio PR #93](https://github.com/openkruise/agentio/pull/93), that limit is
configured by `HTTP_CALLOUT_MAX_RESPONSE_BYTES` at client initialization rather
than by an EPEConfig field.

CRD admission validates the reference's shape, not provider availability.
Missing, unavailable, or wrong-type providers are execution failures handled by
`failStrategy`. The runtime must not substitute a different or default provider.

### Phases and Data Disclosure

At least one of `request` and `response` must be present. Omitting a phase
disables it; an empty object (`request: {}` or `response: {}`) enables a
metadata-only invocation.

- `request` runs before forwarding the request upstream.
- `response` runs on the upstream response. It includes request correlation
  metadata but no request headers or request body.
- Each phase independently configures `headers` and `body`.

Omitting `headers` is equivalent to `mode: None`:

| Mode | Disclosed headers | Required list |
|---|---|---|
| `None` (default) | No headers | Neither list is allowed. |
| `All` | All headers, including credentials and cookies | Neither list is allowed. |
| `AllowList` | Only named headers | Non-empty `allowList`; no `denyList`. |
| `DenyList` | All headers except named headers | Non-empty `denyList`; no `allowList`. |

Header matching is case-insensitive. Lists use set semantics and validate header
names against the API's supported HTTP token pattern, with lengths of 1–256
characters. `None` does not remove invocation metadata such as authority, path,
and content type. `DenyList` can still disclose credentials unless explicitly
excluded.

`body` is a boolean defaulting to `false`. When true, the runtime buffers and
sends the complete body for that phase, so the callout runs after buffering
instead of at the headers phase. Bodies must be valid UTF-8. Response-phase body
disclosure sends only the response body.

`maxBodyBytes` defaults to 1 MiB (1048576 bytes), accepts values from 1 through
8 MiB (8388608 bytes), and limits each disclosed request or response body
separately. Oversized or invalid bodies cause an execution failure; they are
never truncated for inspection. This setting does not configure Envoy's
buffering limit or the size of the provider's decision response.

### Action Ordering and Failure Behavior

The declared action order is `Bypass`, `Block`, `MCPToolPolicy`,
`HeaderManipulation`, `HTTPCallout`, then `TokenTransformation`. Existing terminal
actions can stop evaluation before a callout. A callout is non-terminal unless
it returns an immediate response or encounters a fail-closed execution error.
Every matching rule executes its own configured actions; audit remains
asynchronous after request resolution.

`failStrategy` reuses the existing enum:

| Value | Execution failure behavior |
|---|---|
| `Block` (default) | Reject the request. |
| `Allow` | Skip the failed callout's mutations and continue. |
| `Ignore` | Same current behavior as `Allow`. |

Execution failures include provider lookup, transport, timeout, body-disclosure,
and protocol errors. A valid immediate response from the provider is always
honored, regardless of `failStrategy`; a deliberate denial is not a callout
failure. This API does not prescribe an error response status or body.

### Implementation Details and Constraints

The PR adds the Go API types and action field, regenerates DeepCopy methods,
and adds matching OpenAPI schemas to both profile CRDs. Schema validation
requires a provider name, at least one phase, valid enum values and size bounds,
and agreement between each header mode and its list.

EPEConfig provider registration and configuration watching are separate work in
Agentio PR #93. Runtime conversion and production filter registration must
follow the published agents API. Neither successful admission nor provider
registration alone establishes that the action is executing.

### Risks and Mitigations

- **Sensitive data disclosure:** default to metadata-only calls; use an explicit
  header allowlist and enable bodies only for providers trusted with that data.
- **Latency and buffering cost:** operators configure provider timeouts; policy
  authors limit disclosed bodies. Deployment buffering limits must be aligned
  separately, since `maxBodyBytes` does not change them.
- **Provider outages:** `Block` is the default. Choosing `Allow` or `Ignore`
  explicitly accepts continuing without the failed inspection or its mutations.
- **Partial deployment:** install compatible runtime support before relying on
  a profile for enforcement, and verify actual traffic behavior.

## Alternatives

1. **Inline URL, timeout, and TLS settings per rule.** This duplicates connection
   configuration and couples endpoint rotation to policy edits. Named providers
   keep those settings with their operator owner.
2. **Reuse audit webhooks.** Audit is asynchronous and cannot block or mutate the
   inspected exchange.
3. **Add namespace and kind to the reference.** The current provider registry is
   owned by the serving EPE, and the action already determines the required kind.
   Those fields would imply lookup semantics this API does not provide.
4. **Truncate oversized bodies.** Partial inspection could miss relevant content.
   Complete-body disclosure instead fails according to the selected strategy.

## Upgrade Strategy

The optional field is additive for released profiles; profiles that omit it keep
their existing behavior. This design replaces the unreleased
`externalProcessing.backend.http` shape with `httpCallout.provider.name`.
Experimental users must move connection settings to the provider configuration
and update the action; no compatibility alias is introduced.

Install the updated CRDs and compatible Agentio runtime, configure the named
provider, and then apply profiles using `httpCallout`. Verify request and
response behavior before depending on enforcement. Before rolling back to a
runtime without support, remove or replace callout-dependent policies; admission
of a profile is not proof that an older runtime enforces the action.

## Test Plan

For API implementation validation, run `make generate manifests`, compile the
API package with `go test ./api/v1alpha1`, and check `git diff --check`. API
package compilation alone does not exercise admission or runtime behavior.

Schema validation coverage should include both profile kinds: missing provider
or name, invalid names, neither phase present, empty phases, each header mode,
missing or conflicting lists, defaults, and body-size boundaries.

Follow-up runtime integration must cover request-only and response-only calls,
phase-specific disclosure, UTF-8 and oversized-body failures, missing and
wrong-type providers, timeouts and invalid decisions, the failure-strategy
matrix, immediate responses, mutations, and action ordering. These are runtime
acceptance criteria, not capabilities verified by this API-only PR.

## Implementation History

- 2026-10-20: Proposal added to agents PR #882 for the named HTTP callout API.
- Follow-up: consume the published API and enable the action in Agentio's
  production filter pipeline.
