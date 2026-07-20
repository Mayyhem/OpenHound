---
id: ope-b1e8
status: open
deps: []
links: []
created: 2026-07-20T14:33:28Z
type: bug
priority: 3
tags: [sccm, cli, collect]
---

# Dead collect flag: --sms / --sms-provider accepted but ignored

The --sms / --sms-provider CLI flag on 'openhound collect sccm' is accepted and forwarded into source() but never actually read there, so it does nothing for scoping a run to a specific SMS provider. -c/--computers is what actually seeds a specific host. Found incidentally during ope-b916 live validation against ps1-sms. Either wire --sms into source()'s target seeding or remove/deprecate the flag and document -c as the scoping mechanism. Pre-existing, unrelated to the CVE feature.
