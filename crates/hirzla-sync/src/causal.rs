//! Causal order of a journal (§ 2): past, concurrency, total order.

use std::collections::BTreeMap;

use hirzla_vault::model::OpId;

/// A fixed-size set of operation indices.
#[derive(Clone, Default, PartialEq, Eq)]
struct BitSet(Vec<u64>);

impl BitSet {
    fn with_len(n: usize) -> Self {
        BitSet(vec![0; n.div_ceil(64)])
    }

    fn insert(&mut self, i: usize) {
        if let Some(w) = self.0.get_mut(i / 64) {
            *w |= 1 << (i % 64);
        }
    }

    fn contains(&self, i: usize) -> bool {
        self.0.get(i / 64).is_some_and(|w| w & (1 << (i % 64)) != 0)
    }

    fn union_with(&mut self, other: &BitSet) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= *b;
        }
    }
}

/// The causal graph of the operations that passed steps 1 to 7 of § 6.
///
/// Operations are indexed in the total order `(lamport, op_id)` (§ 2), which extends the
/// causal order (§ 4.3), so every dependency has a smaller index than its dependant.
pub struct Causality {
    order: Vec<OpId>,
    lamport: Vec<u64>,
    index: BTreeMap<OpId, usize>,
    past: Vec<BitSet>,
}

impl Causality {
    /// Builds the graph from `(op_id, lamport, deps)`. Dependencies outside the set are
    /// ignored (they are pruned stubs without known history, ADR 0017).
    #[must_use]
    pub(crate) fn build(nodes: &[(OpId, u64, Vec<OpId>)]) -> Self {
        let mut sorted: Vec<&(OpId, u64, Vec<OpId>)> = nodes.iter().collect();
        sorted.sort_by_key(|a| (a.1, a.0));
        let n = sorted.len();
        let index: BTreeMap<OpId, usize> =
            sorted.iter().enumerate().map(|(i, x)| (x.0, i)).collect();
        let mut past: Vec<BitSet> = Vec::with_capacity(n);
        for (i, (_, _, deps)) in sorted.iter().map(|x| (x.0, x.1, &x.2)).enumerate() {
            let mut p = BitSet::with_len(n);
            for d in deps {
                if let Some(&j) = index.get(d) {
                    // Holds by construction: the lamport rule makes dependencies smaller.
                    if j < i {
                        p.insert(j);
                        let dp = past[j].clone();
                        p.union_with(&dp);
                    }
                }
            }
            past.push(p);
        }
        Causality {
            order: sorted.iter().map(|x| x.0).collect(),
            lamport: sorted.iter().map(|x| x.1).collect(),
            index,
            past,
        }
    }

    /// Number of operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Operations in total order.
    #[must_use]
    pub fn total_order(&self) -> &[OpId] {
        &self.order
    }

    /// Whether `op` is in the graph.
    #[must_use]
    pub fn contains(&self, op: &OpId) -> bool {
        self.index.contains_key(op)
    }

    /// Lamport clock of `op`.
    #[must_use]
    pub fn lamport(&self, op: &OpId) -> Option<u64> {
        self.index.get(op).map(|&i| self.lamport[i])
    }

    /// Position of `op` in the total order.
    #[must_use]
    pub fn position(&self, op: &OpId) -> Option<usize> {
        self.index.get(op).copied()
    }

    /// `a ∈ past(b)`.
    #[must_use]
    pub fn precedes(&self, a: &OpId, b: &OpId) -> bool {
        match (self.index.get(a), self.index.get(b)) {
            (Some(&i), Some(&j)) => self.past[j].contains(i),
            _ => false,
        }
    }

    /// `a` and `b` are distinct and neither is in the past of the other.
    #[must_use]
    pub fn concurrent(&self, a: &OpId, b: &OpId) -> bool {
        a != b
            && self.contains(a)
            && self.contains(b)
            && !self.precedes(a, b)
            && !self.precedes(b, a)
    }

    /// `past(b)`, in total order.
    #[must_use]
    pub fn past(&self, b: &OpId) -> Vec<OpId> {
        match self.index.get(b) {
            Some(&j) => (0..j)
                .filter(|&i| self.past[j].contains(i))
                .map(|i| self.order[i])
                .collect(),
            None => Vec::new(),
        }
    }

    /// Heads of the whole graph: operations in the past of no other.
    #[must_use]
    pub fn heads(&self) -> Vec<OpId> {
        let n = self.order.len();
        let mut covered = BitSet::with_len(n);
        for p in &self.past {
            covered.union_with(p);
        }
        (0..n)
            .filter(|&i| !covered.contains(i))
            .map(|i| self.order[i])
            .collect()
    }

    /// Heads of a subset of the graph (by predicate), as seen within that subset.
    #[must_use]
    pub fn heads_of(&self, members: &[OpId]) -> Vec<OpId> {
        members
            .iter()
            .filter(|a| !members.iter().any(|b| self.precedes(a, b)))
            .copied()
            .collect()
    }
}
