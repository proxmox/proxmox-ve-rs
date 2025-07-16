use core::hash::Hash;
use std::cmp::Eq;
use std::collections::HashSet;

pub mod valid;

#[derive(Clone, Debug, Default)]
pub struct Allowlist<T>(HashSet<T>);

impl<T: Hash + Eq> FromIterator<T> for Allowlist<T> {
    fn from_iter<A>(iter: A) -> Self
    where
        A: IntoIterator<Item = T>,
    {
        Allowlist(HashSet::from_iter(iter))
    }
}

/// returns true if [`value`] is in the allowlist or if allowlist does not exist
impl<T: Hash + Eq> Allowlist<T> {
    pub fn is_allowed(&self, value: &T) -> bool {
        self.0.contains(value)
    }
}

impl<T: Hash + Eq> Allowlist<T> {
    pub fn new<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self::from_iter(iter)
    }
}
