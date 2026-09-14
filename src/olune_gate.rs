//! OLUNE ACCESS gate — valida o token de convite enviado pelo cliente (campo `token` de
//! PunchHoleRequest/RequestRelay) contra o banco do Olune Access (sqlite, tabelas invites/devices).
//! Ativado apenas quando a variável OLUNE_ACCESS_DB aponta para o arquivo do banco; sem ela, o hbbs
//! se comporta exatamente como o upstream.
use hbb_common::log;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub enum Verdict {
    Allow,
    Deny(String),
}

const CACHE_TTL: Duration = Duration::from_secs(10);

lazy_static::lazy_static! {
    static ref CACHE: Mutex<HashMap<String, (Instant, Verdict)>> = Mutex::new(HashMap::new());
}
static POOL: hbb_common::tokio::sync::OnceCell<Option<SqlitePool>> =
    hbb_common::tokio::sync::OnceCell::const_new();

pub fn enabled() -> bool {
    std::env::var("OLUNE_ACCESS_DB").map(|p| !p.trim().is_empty()).unwrap_or(false)
}

async fn pool() -> Option<SqlitePool> {
    POOL.get_or_init(|| async {
        let path = std::env::var("OLUNE_ACCESS_DB").ok()?;
        match SqlitePoolOptions::new()
            .max_connections(2)
            .connect(&format!("sqlite://{}?mode=rw", path))
            .await
        {
            Ok(p) => {
                log::info!("olune gate: banco de convites aberto em {}", path);
                Some(p)
            }
            Err(e) => {
                log::error!("olune gate: falha ao abrir {}: {}", path, e);
                None
            }
        }
    })
    .await
    .clone()
}

/// Decide se o portador de `token` pode iniciar uma sessão com `target_id`.
pub async fn check(token: &str, target_id: &str) -> Verdict {
    if !enabled() {
        return Verdict::Allow;
    }
    let token = token.trim();
    if token.is_empty() {
        return Verdict::Deny("Olune: este aparelho não tem convite. Abra o Olune Remote e informe o código de convite.".into());
    }
    let key = format!("{}|{}", token, target_id);
    if let Some((t, v)) = CACHE.lock().unwrap().get(&key) {
        if t.elapsed() < CACHE_TTL {
            return v.clone();
        }
    }
    let verdict = query(token, target_id).await;
    CACHE.lock().unwrap().insert(key, (Instant::now(), verdict.clone()));
    verdict
}

async fn query(token: &str, target_id: &str) -> Verdict {
    let Some(pool) = pool().await else {
        // Banco indisponível: nega (fail-closed) para não abrir o relay a qualquer um.
        return Verdict::Deny("Olune: serviço de convites indisponível; tente novamente em instantes.".into());
    };
    let row = sqlx::query(
        "SELECT i.status, i.monthly_minutes, i.used_minutes, i.month_key, i.allowed_ids, i.name \
         FROM devices d JOIN invites i ON i.id = d.invite_id WHERE d.token = ? AND d.revoked = 0",
    )
    .bind(token)
    .fetch_optional(&pool)
    .await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return Verdict::Deny("Olune: convite inválido ou removido.".into()),
        Err(e) => {
            log::error!("olune gate: consulta falhou: {}", e);
            return Verdict::Deny("Olune: serviço de convites indisponível.".into());
        }
    };
    let status: String = row.get("status");
    let monthly: i64 = row.get("monthly_minutes");
    let mut used: i64 = row.get("used_minutes");
    let month_key: String = row.get("month_key");
    let allowed: String = row.get("allowed_ids");
    let name: String = row.get("name");
    if status == "suspended" {
        return Verdict::Deny(format!("Olune: o convite de {} está suspenso.", name));
    }
    if status != "active" {
        return Verdict::Deny("Olune: convite inválido ou removido.".into());
    }
    if month_key != chrono::Utc::now().format("%Y-%m").to_string() {
        used = 0; // cota mensal renovada (o serviço zera na próxima consulta)
    }
    if monthly > 0 && used >= monthly {
        return Verdict::Deny(format!("Olune: {} esgotou as horas deste mês.", name));
    }
    if allowed != "*" {
        let ok = serde_json::from_str::<Vec<String>>(&allowed)
            .map(|v| v.iter().any(|x| x == target_id))
            .unwrap_or(false);
        if !ok {
            return Verdict::Deny("Olune: este convite não permite acessar este computador.".into());
        }
    }
    Verdict::Allow
}
