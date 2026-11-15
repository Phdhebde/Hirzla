//! The causal relation between operations, as the authorisation calculation needs it.

use std::collections::HashMap;

use hirzla_vault::model::OpId;

/// The causal past of operations (`sync-protocol.md` § 2). `hirzla-sync` owns the journal and
/// implements it on its own graph; [`Dag`] is a self-contained implementation.
pub trait Causality {
    /// Whether `a ∈ past(b)`: `a` is reachable from `b.deps`, recursively.
    fn precedes(&self, a: &OpId, b: &OpId) -> bool;

    /// Whether `a` and `b` are distinct and concurrent: neither is in the past of the other.
    fn concurrent(&self, a: &OpId, b: &OpId) -> bool {
        a != b && !self.precedes(a, b) && !self.precedes(b, a)
    }
}

/// A causal graph built from `(op_id, deps)` pairs, with the transitive closure computed once.
/// Dependencies that are not in the graph (pruned or unknown) are ignored.
#[derive(Debug, Clone, Default)]
pub struct Dag {
    index: HashMap<OpId, usize>,
    /// `ancestors[i]`: bit set of the indices in `past(i)`.
    ancestors: Vec<Vec<u64>>,
}

impl Dag {
    /// Builds the graph.
    pub fn new<'a, I>(nodes: I) -> Dag
    where
        I: IntoIterator<Item = (OpId, &'a [OpId])>,
    {
        let nodes: Vec<(OpId, &[OpId])> = nodes.into_iter().collect();
        let mut index = HashMap::with_capacity(nodes.len());
        for (id, _) in &nodes {
            let next = index.len();
            index.entry(*id).or_insert(next);
        }
        let n = index.len();
        let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (id, ds) in &nodes {
            if let Some(&i) = index.get(id) {
                deps[i].extend(ds.iter().filter_map(|d| index.get(d).copied()));
            }
        }
        let words = n.div_ceil(64);
        let mut ancestors = vec![vec![0u64; words]; n];
        // 0 unvisited, 1 in progress, 2 done. Iterative post-order; a back edge (impossible
        // with hash identifiers) is ignored.
        let mut state = vec![0u8; n];
        for root in 0..n {
            if state[root] == 2 {
                continue;
            }
            let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
            state[root] = 1;
            while let Some(top) = stack.len().checked_sub(1) {
                let (v, i) = stack[top];
                if let Some(&d) = deps[v].get(i) {
                    stack[top].1 += 1;
                    if state[d] == 0 {
                        state[d] = 1;
                        stack.push((d, 0));
                    }
                    continue;
                }
                let mut bits = vec![0u64; words];
                for &d in &deps[v] {
                    if state[d] == 2 {
                        bits[d / 64] |= 1 << (d % 64);
                        for (w, a) in bits.iter_mut().zip(&ancestors[d]) {
                            *w |= *a;
                        }
                    }
                }
                ancestors[v] = bits;
                state[v] = 2;
                stack.pop();
            }
        }
        Dag { index, ancestors }
    }
}

impl Causality for Dag {
    fn precedes(&self, a: &OpId, b: &OpId) -> bool {
        match (self.index.get(a), self.index.get(b)) {
            (Some(&a), Some(&b)) => self.ancestors[b][a / 64] & (1 << (a % 64)) != 0,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> OpId {
        [n; 48]
    }

    #[test]
    fn transitive_past_and_concurrency() {
        // 1 <- 2 <- 4, 1 <- 3 <- 4, 5 alone.
        let d2 = [id(1)];
        let d3 = [id(1)];
        let d4 = [id(2), id(3)];
        let dag = Dag::new([
            (id(4), &d4[..]),
            (id(1), &[][..]),
            (id(2), &d2[..]),
            (id(3), &d3[..]),
            (id(5), &[][..]),
        ]);
        assert!(dag.precedes(&id(1), &id(4)));
        assert!(dag.precedes(&id(2), &id(4)));
        assert!(!dag.precedes(&id(4), &id(1)));
        assert!(!dag.precedes(&id(1), &id(1)));
        assert!(dag.concurrent(&id(2), &id(3)));
        assert!(dag.concurrent(&id(5), &id(4)));
        assert!(!dag.concurrent(&id(1), &id(1)));
        assert!(!dag.precedes(&id(9), &id(4)));
    }
}
