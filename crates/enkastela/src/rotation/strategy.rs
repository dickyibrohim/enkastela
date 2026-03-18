//! Key rotation strategies.

/// How to handle data encrypted with old key versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RotationStrategy {
    /// Re-encrypt data when it is next read.
    /// Low overhead but old-version data persists until accessed.
    #[default]
    Lazy,
    /// Background batch process re-encrypts all data.
    /// Higher resource usage but ensures complete migration.
    Eager {
        /// Number of rows to process per batch.
        batch_size: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_lazy() {
        assert_eq!(RotationStrategy::default(), RotationStrategy::Lazy);
    }

    #[test]
    fn eager_stores_batch_size() {
        let strategy = RotationStrategy::Eager { batch_size: 500 };
        match strategy {
            RotationStrategy::Eager { batch_size } => assert_eq!(batch_size, 500),
            _ => panic!("expected Eager"),
        }
    }

    #[test]
    fn clone_and_copy() {
        let s = RotationStrategy::Eager { batch_size: 100 };
        let s2 = s;
        assert_eq!(s, s2);
    }
}
