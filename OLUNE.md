# olune-hbbs — RustDesk Server OSS 1.1.16 + Olune Access gate

Fork mínimo do RustDesk Server (AGPL-3.0) para o Olune Remote. Única mudança funcional: `src/olune_gate.rs`
valida o campo `token` de `PunchHoleRequest`/`RequestRelay` contra o banco do Olune Access (sqlite,
tabelas `invites`/`devices`) quando a variável `OLUNE_ACCESS_DB` está definida. Sem a variável, comporta-se
como o upstream. Recusas retornam `other_failure`/`refuse_reason` com a razão (convite inválido, suspenso,
horas esgotadas, computador não permitido). Build via GitHub Actions (tag `v*`).
