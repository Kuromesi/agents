---
title: SecurityProfile HTTP callouts with named providers
creation-date: 2026-09-21
last-updated: 2026-09-21
status: provisional
---

# SecurityProfile HTTP callouts with named providers

## Summary

Add `rules[].actions.httpCallout` to SecurityProfile and GlobalSecurityProfile.
The action references a named HTTP callout provider in the serving EPE's
configuration. Profile authors choose which request and response data to disclose
and what to do if the callout fails. Operators configure provider connections once
in EPEConfig and can update them without editing every profile.

This revises the unreleased `externalProcessing` API proposed in
[PR #882](https://github.com/openkruise/agents/pull/882). It defines the API and CRD
contract; Agentio's SecurityProfile adapter still needs to consume the published
API before policies can execute this action.

## Motivation and scope

Inline URLs, timeouts, and TLS settings mix shared connection configuration with
per-rule policy. They also allow a profile to choose arbitrary destinations.
Named providers separate these responsibilities and match EPEConfig's existing
`extensionProviders` registry. Other provider kinds can be added to that registry
without expanding this action into a transport union.

This proposal covers HTTP callouts only. Credential-provider selection,
credential identity, streaming bodies, and the Envoy-to-EPE ext_proc API are
separate concerns. HTTP callouts do not require a sandbox token. Provider TLS
authentication is configured in EPEConfig; workload metadata in an invocation
does not by itself authenticate the EPE connection.

## API

An operator registers the provider in the base EPEConfig ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agentio-epe-config
  namespace: agentio-system
data:
  config: |
    extensionProviders:
    - name: content-scanner
      httpCallout:
        url: https://scanner.security.svc/v1/process
        timeout: 500ms
        maxResponseBytes: 1048576
        tls:
          caSecretRef:
            name: scanner-ca
          clientCertificateSecretRef:
            name: epe-client
```

A SecurityProfile rule references it:

```yaml
actions:
  httpCallout:
    providerRef:
      name: content-scanner
    request:
      headers:
        mode: AllowList
        allowList: [content-type, x-request-id]
      body: true
    response:
      body: true
    maxBodyBytes: 1048576
    failStrategy: Block
```

- `providerRef.name` is a required DNS subdomain name matching an `httpCallout` entry in
  the serving EPE's effective EPEConfig. It is not a Kubernetes object reference
  and has no namespace, kind, or implicit default. A credential provider with the
  same referenced name cannot satisfy this action.
- At least one of `request` and `response` must be present. Omission disables that
  phase; `{}` enables a metadata-only callout. Defaulting never enables a phase.
- `headers.mode` defaults to `None`. `All` sends every header, including
  credentials and cookies. `AllowList` and `DenyList` require the corresponding
  nonempty list and prohibit the other list. Names match case-insensitively.
  Request correlation fields, including path, query, and content type, remain
  in the invocation even with mode `None`.
- `body` defaults to `false`. If true, EPE invokes the provider after buffering
  the complete body for that direction. Otherwise it calls at the headers phase.
  Bodies must be valid UTF-8. A response invocation carries response data and
  request correlation metadata, never request headers or the request body.
- `maxBodyBytes` defaults to 1 MiB, with an allowed range of 1 byte through 8 MiB.
  It bounds each disclosed request or response body; exceeding it is an error,
  not permission to send a truncated body. It does not configure Envoy's buffer
  limits. Provider `maxResponseBytes` independently bounds the decision JSON.
- `failStrategy` reuses the existing `Block`, `Allow`, and `Ignore` enum and
  defaults to `Block`. Provider lookup, transport, timeout, invalid body, and
  protocol failures follow this strategy. `Allow` and `Ignore` skip the failed
  callout's mutations. A valid immediate response from the provider is always
  honored, regardless of the failure strategy.

Within a rule, HTTPCallout follows HeaderManipulation and precedes
TokenTransformation. A provider decision may continue processing with mutations
or terminate the exchange with an immediate response. Audit remains asynchronous.

## Validation and runtime integration

CRD validation checks the provider name, enabled phases, header-mode/list
consistency, enum values, and body limit. It cannot validate a reference against
EPEConfig because that configuration belongs to the serving EPE. Missing,
wrong-type, or unavailable providers are runtime failures; they do not select a
different provider or retain a removed provider as a fallback.

EPEConfig updates apply to subsequent exchanges without requiring a profile edit.
The action must not copy provider connection settings into a compiled profile.
The Agentio adapter will map `providerRef.name` to the filter's `provider`,
preserve phase pointer presence, map header modes to the
filter's lowercase enum and `allowList`/`denyList` to `allowlist`/`denylist`, and map
`Allow`/`Ignore` to `failOpen: true`. It must apply the same defaults and validation
to profiles received outside Kubernetes admission.

## Alternatives

- Inline provider settings repeat connection configuration and make certificate
  and endpoint updates require profile changes.
- A plain `provider` string avoids nesting, but `providerRef.name` follows the
  reference-object style used elsewhere in SecurityProfile. Only `name` is needed:
  there is one registry scope and the action determines the provider type.
- A transport union under `externalProcessing` is unnecessary for an HTTP-only
  action. Future protocols should define their own policy semantics.
- `bodyMode: Never/Always` adds an enum for the two supported behaviors. A boolean
  directly expresses the opt-in buffering and disclosure implemented today.

## Compatibility and upgrade

The old `externalProcessing` field exists only in the unmerged API proposal. This
revision replaces that proposal rather than adding a compatibility alias. Existing
released actions are unchanged.

For experimental installations of the earlier CRD, export affected profiles before
upgrading. Move `backend.http.url` and `timeout` into an EPEConfig HTTPCallout
provider; rename the action to `httpCallout` and reference its name with
`providerRef.name`.
Map `bodyMode: Always` to `body: true`, and `Never` or omission to `body: false` or
omission. Keep `maxBodyBytes` on the action and also configure provider
`maxResponseBytes` with the old value to retain the previous shared limit.
Header modes and `failStrategy` retain their meanings.

Install a consumer that supports the new API along with the revised CRDs, then
reapply the migrated profiles. Do not assume Kubernetes renames stored fields;
old `externalProcessing` data can be pruned by the revised schema. Rollback of an
experimental deployment requires restoring both its old CRD and exported profiles.

## Validation plan

Regenerate DeepCopy, clients, and both profile CRDs. Exercise the generated
OpenAPI and CEL schemas for defaults, request/response presence, provider names,
header disclosure combinations, and body limits. Cluster callout tests follow
when Agentio consumes the API and mounts the filter in its production chain.
