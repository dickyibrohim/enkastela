//! Health check for enkastela subsystems.

/// Health status of an individual subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

/// Aggregated health status across all subsystems.
#[derive(Debug, Clone)]
pub struct HealthStatus {
    pub overall: Health,
    pub key_cache: Health,
    pub audit_logger: Health,
}

impl HealthStatus {
    /// Computes overall health from subsystem statuses.
    ///
    /// If any subsystem is Unhealthy, overall is Unhealthy (with the first unhealthy reason).
    /// If any is Degraded but none Unhealthy, overall is Degraded.
    /// Otherwise, overall is Healthy.
    pub fn compute(key_cache: Health, audit_logger: Health) -> Self {
        let overall = match (&key_cache, &audit_logger) {
            (Health::Unhealthy(reason), _) => Health::Unhealthy(reason.clone()),
            (_, Health::Unhealthy(reason)) => Health::Unhealthy(reason.clone()),
            (Health::Degraded(reason), _) => Health::Degraded(reason.clone()),
            (_, Health::Degraded(reason)) => Health::Degraded(reason.clone()),
            _ => Health::Healthy,
        };

        Self {
            overall,
            key_cache,
            audit_logger,
        }
    }

    /// Returns true if overall health is Healthy.
    pub fn is_healthy(&self) -> bool {
        self.overall == Health::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_healthy() {
        let status = HealthStatus::compute(Health::Healthy, Health::Healthy);
        assert_eq!(status.overall, Health::Healthy);
        assert!(status.is_healthy());
        assert_eq!(status.key_cache, Health::Healthy);
        assert_eq!(status.audit_logger, Health::Healthy);
    }

    #[test]
    fn key_cache_degraded() {
        let status = HealthStatus::compute(
            Health::Degraded("high eviction rate".into()),
            Health::Healthy,
        );
        assert_eq!(
            status.overall,
            Health::Degraded("high eviction rate".into())
        );
        assert!(!status.is_healthy());
    }

    #[test]
    fn audit_logger_degraded() {
        let status = HealthStatus::compute(
            Health::Healthy,
            Health::Degraded("queue backpressure".into()),
        );
        assert_eq!(
            status.overall,
            Health::Degraded("queue backpressure".into())
        );
        assert!(!status.is_healthy());
    }

    #[test]
    fn key_cache_unhealthy() {
        let status = HealthStatus::compute(
            Health::Unhealthy("cache connection lost".into()),
            Health::Healthy,
        );
        assert_eq!(
            status.overall,
            Health::Unhealthy("cache connection lost".into())
        );
        assert!(!status.is_healthy());
    }

    #[test]
    fn audit_logger_unhealthy() {
        let status = HealthStatus::compute(
            Health::Healthy,
            Health::Unhealthy("database unreachable".into()),
        );
        assert_eq!(
            status.overall,
            Health::Unhealthy("database unreachable".into())
        );
        assert!(!status.is_healthy());
    }

    #[test]
    fn both_unhealthy_takes_first() {
        let status = HealthStatus::compute(
            Health::Unhealthy("cache down".into()),
            Health::Unhealthy("audit down".into()),
        );
        // key_cache is checked first, so its reason wins
        assert_eq!(status.overall, Health::Unhealthy("cache down".into()));
        assert!(!status.is_healthy());
    }

    #[test]
    fn unhealthy_overrides_degraded() {
        let status = HealthStatus::compute(
            Health::Degraded("slow cache".into()),
            Health::Unhealthy("audit failed".into()),
        );
        assert_eq!(status.overall, Health::Unhealthy("audit failed".into()));
        assert!(!status.is_healthy());
    }

    #[test]
    fn both_degraded_takes_first() {
        let status = HealthStatus::compute(
            Health::Degraded("cache pressure".into()),
            Health::Degraded("audit lag".into()),
        );
        assert_eq!(status.overall, Health::Degraded("cache pressure".into()));
        assert!(!status.is_healthy());
    }
}
