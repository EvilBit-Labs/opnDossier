# Architecture

opnDossier's architecture documentation has been split into focused sub-documents. Start with the overview and follow the cross-links for deeper detail on the pipeline and the plugin system.

> **Note on deep links:** external references of the form `architecture.md#some-anchor` may no longer resolve. Section-level anchors now live in the sub-documents linked below.

- **[Overview](architecture/overview.md)** — design principles, technology stack, public package boundaries, top-level components, the `CommonDevice` data model, multi-device support, and cross-cutting concerns (air-gap, security, deployment).
- **[Pipelines](architecture/pipelines.md)** — the DeviceParser registry, the parse → convert → enrich → render pipeline, the programmatic markdown generation architecture, the FormatRegistry dispatch layer, the warning system, and the versioning strategy.
- **[Plugin System](architecture/plugin-system.md)** — the audit command surface, the compliance plugin registry and trust model, the dynamic loader, and the panic-recovery contract.
