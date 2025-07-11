//! Bijections between sets of unique elements.
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    sync::Arc,
};

use crate::category;

type Lookup<A, B> = Arc<dyn Fn(&A) -> Option<B>>;

/// A Bijection is a two way lookup.
#[allow(missing_debug_implementations, reason = "internal closures")]
pub struct Bijection<A: Clone + 'static, B: Clone + 'static> {
    forward: Lookup<A, B>,
    reverse: Lookup<B, A>,
}
impl<A: Clone, B: Clone> Bijection<A, B> {
    /// Finds the unique corresponding value B for a given A
    pub fn lookup(&self, a: &A) -> Option<B> {
        (self.forward)(a)
    }

    /// Inverts the Bijection
    pub fn invert(self) -> Bijection<B, A> {
        Bijection {
            forward: self.reverse,
            reverse: self.forward,
        }
    }

    /// Composes two Bijections. Note: If the codomain of self doesn't perfectly match the domain of
    /// other, then the composed Bijection won't behave as expected.
    pub fn comp<C: Clone>(&self, other: &Bijection<B, C>) -> Bijection<A, C> {
        let forward_ab = self.forward.clone();
        let forward_bc = other.forward.clone();
        let reverse_cb = other.reverse.clone();
        let reverse_ba = self.reverse.clone();

        let forward = Arc::new(move |a: &A| forward_ab(a).and_then(category::moved(&*forward_bc)));
        let reverse = Arc::new(move |c: &C| reverse_cb(c).and_then(category::moved(&*reverse_ba)));
        Bijection { forward, reverse }
    }
}

impl<A: Ord + Clone, B: Ord + Clone> TryFrom<BTreeMap<A, B>> for Bijection<A, B> {
    type Error = B;

    fn try_from(value: BTreeMap<A, B>) -> Result<Self, Self::Error> {
        let mut reverse_map = BTreeMap::new();
        for (a, b) in value {
            if reverse_map.contains_key(&b) {
                return Err(b);
            } else {
                reverse_map.insert(Arc::new(b), Arc::new(a));
            }
        }

        let forward_map = reverse_map
            .iter()
            .map(|(b, a)| (a.clone(), b.clone()))
            .collect::<BTreeMap<Arc<A>, Arc<B>>>();

        let forward = Arc::new(move |a: &A| forward_map.get(a).map(Arc::as_ref).cloned());
        let reverse = Arc::new(move |b: &B| reverse_map.get(b).map(Arc::as_ref).cloned());

        Ok(Bijection { forward, reverse })
    }
}

impl<A: Hash + Eq + Clone, B: Hash + Eq + Clone> TryFrom<HashMap<A, B>> for Bijection<A, B> {
    type Error = B;

    fn try_from(value: HashMap<A, B>) -> Result<Self, Self::Error> {
        let mut reverse_map = HashMap::new();
        for (a, b) in value {
            if reverse_map.contains_key(&b) {
                return Err(b);
            } else {
                reverse_map.insert(Arc::new(b), Arc::new(a));
            }
        }

        let forward_map = reverse_map
            .iter()
            .map(|(b, a)| (a.clone(), b.clone()))
            .collect::<HashMap<Arc<A>, Arc<B>>>();

        let forward = Arc::new(move |a: &A| forward_map.get(a).map(Arc::as_ref).cloned());
        let reverse = Arc::new(move |b: &B| reverse_map.get(b).map(Arc::as_ref).cloned());

        Ok(Bijection { forward, reverse })
    }
}
