use crate::hasher::Hasher;
use crate::{
    Digest, HashTree, HashTreeBuilder, Label, LabeledTree, MixedHashTree, Path, TreeHashError,
    Witness, WitnessGenerator,
};
use std::collections::{BTreeMap, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;

#[cfg(test)]
mod tests;

const DOMAIN_HASHTREE_LEAF: &str = "ic-hashtree-leaf";
const DOMAIN_HASHTREE_EMPTY_SUBTREE: &str = "ic-hashtree-empty";
const DOMAIN_HASHTREE_NODE: &str = "ic-hashtree-labeled";
const DOMAIN_HASHTREE_FORK: &str = "ic-hashtree-fork";

// Helpers for creation of domain-separated hashers.
pub(crate) fn new_leaf_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_LEAF)
}

pub(crate) fn new_fork_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_FORK)
}

pub(crate) fn new_node_hasher() -> Hasher {
    Hasher::for_domain(DOMAIN_HASHTREE_NODE)
}

pub(crate) fn empty_subtree_hash() -> Digest {
    Hasher::for_domain(DOMAIN_HASHTREE_EMPTY_SUBTREE).finalize()
}

// Wraps the given hash_tree into a HashTree::HashNode.
fn into_hash_node(label: &Label, hash_tree: HashTree) -> HashTree {
    let mut hasher = new_node_hasher();
    hasher.update(label.as_bytes());
    hasher.update(&hash_tree.digest().0);
    let digest = hasher.finalize();
    HashTree::Node {
        digest,
        label: label.to_owned(),
        hash_tree: Box::new(hash_tree),
    }
}

// Wraps the given left_tree and right_tree into HashTree::HashFork.
fn into_fork(left_tree: HashTree, right_tree: HashTree) -> HashTree {
    let mut hasher = new_fork_hasher();
    hasher.update(&left_tree.digest().0);
    hasher.update(&right_tree.digest().0);
    let digest = hasher.finalize();
    HashTree::Fork {
        digest,
        left_tree: Box::new(left_tree),
        right_tree: Box::new(right_tree),
    }
}

// Wraps the given hash_trees pairwise into HashTree::HashFork-entries.
// panic!s if hash_trees is empty or has an odd number of entries.
fn into_pairwise_forks(mut hash_trees: VecDeque<HashTree>) -> VecDeque<HashTree> {
    if hash_trees.is_empty() || hash_trees.len() % 2 != 0 {
        panic!("Illegal state: an even number of hash trees required");
    }
    let mut forks = VecDeque::new();
    while !hash_trees.is_empty() {
        let left_tree = hash_trees.pop_front().unwrap();
        let right_tree = hash_trees.pop_front().unwrap();
        forks.push_back(into_fork(left_tree, right_tree));
    }
    forks
}

// Wraps the given hash_trees into a single HashTree, maintaining
// the order of the subtrees.
fn into_hash_tree(mut hash_trees: VecDeque<HashTree>) -> HashTree {
    match hash_trees.len() {
        // an empty subtree
        0 => HashTree::Leaf {
            digest: empty_subtree_hash(),
        },
        // a subtree with a single sub-subtree
        1 => hash_trees.pop_front().unwrap(),
        // a subtree with at least 2 sub-subtrees
        n => {
            if n % 2 == 0 {
                // even number, make forks in pairs
                into_hash_tree(into_pairwise_forks(hash_trees))
            } else {
                // odd number, forks in pairs plus a singleton
                let singleton = hash_trees.pop_back().unwrap();
                let mut forks = into_pairwise_forks(hash_trees);
                forks.push_back(singleton);
                into_hash_tree(forks)
            }
        }
    }
}

fn write_labeled_tree<T: Debug>(
    tree: &LabeledTree<T>,
    level: u8,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let indent = String::from_utf8(vec![b' '; (level * 8) as usize]).unwrap();
    match tree {
        LabeledTree::Leaf(t) => writeln!(f, "{}\\__ leaf:{:?}", indent, t),
        LabeledTree::SubTree(children) => {
            for child in children {
                writeln!(f, "{}+-- {}:", indent, child.0)?;
                write_labeled_tree(child.1, level + 1, f)?;
            }
            write!(f, "")
        }
    }
}

fn write_hash_tree(tree: &HashTree, level: u8, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let indent = String::from_utf8(vec![b' '; (level * 8) as usize]).unwrap();
    match tree {
        HashTree::Leaf { digest } => writeln!(f, "{}\\__leaf:{:?}", indent, digest),
        HashTree::Fork {
            digest,
            left_tree,
            right_tree,
        } => {
            writeln!(f, "{}+-- fork:{:?}", indent, digest)?;
            write_hash_tree(left_tree, level + 1, f)?;
            write_hash_tree(right_tree, level + 1, f)
        }
        HashTree::Node {
            digest,
            label,
            hash_tree,
        } => {
            writeln!(f, "{}--- node: [{}], {:?}", indent, label, digest)?;
            write_hash_tree(hash_tree, level + 1, f)
        }
    }
}

pub(crate) fn compute_leaf_digest(contents: &[u8]) -> Digest {
    let mut hasher = new_leaf_hasher();
    hasher.update(contents);
    hasher.finalize()
}

pub(crate) fn compute_node_digest(label: &Label, subtree_digest: &Digest) -> Digest {
    let mut hasher = new_node_hasher();
    hasher.update(label.as_bytes());
    hasher.update(&subtree_digest.0);
    hasher.finalize()
}

pub(crate) fn compute_fork_digest(left_digest: &Digest, right_digest: &Digest) -> Digest {
    let mut hasher = new_fork_hasher();
    hasher.update(&left_digest.0);
    hasher.update(&right_digest.0);
    hasher.finalize()
}

fn compute_subtree_digest(
    witness: &Witness,
    subtree_digests: &BTreeMap<Label, Digest>,
    curr_path: &mut Vec<Label>,
) -> Result<Digest, TreeHashError> {
    match witness {
        Witness::Pruned { digest } => Ok(digest.to_owned()),
        Witness::Node { label, .. } => {
            curr_path.push(label.to_owned());
            if let Some(subtree_digest) = subtree_digests.get(label) {
                curr_path.pop();
                Ok(compute_node_digest(label, subtree_digest))
            } else {
                Err(TreeHashError::InconsistentPartialTree {
                    offending_path: curr_path.to_owned(),
                })
            }
        }
        Witness::Fork {
            left_tree,
            right_tree,
        } => {
            let left_digest = compute_subtree_digest(left_tree, subtree_digests, curr_path)?;
            let right_digest = compute_subtree_digest(right_tree, subtree_digests, curr_path)?;
            Ok(compute_fork_digest(&left_digest, &right_digest))
        }
        _ => Err(TreeHashError::InconsistentPartialTree {
            offending_path: curr_path.to_owned(),
        }),
    }
}

fn recompute_digest_impl(
    partial_tree: &LabeledTree<Vec<u8>>,
    witness: &Witness,
    curr_path: &mut Vec<Label>,
) -> Result<Digest, TreeHashError> {
    match partial_tree {
        LabeledTree::Leaf(contents) => {
            if *witness == Witness::Known() {
                Ok(compute_leaf_digest(&contents))
            } else {
                Err(TreeHashError::InconsistentPartialTree {
                    offending_path: curr_path.to_owned(),
                })
            }
        }
        LabeledTree::SubTree(children) if children.is_empty() => {
            if *witness == Witness::Known() {
                Ok(empty_subtree_hash())
            } else {
                Err(TreeHashError::InconsistentPartialTree {
                    offending_path: curr_path.to_owned(),
                })
            }
        }
        LabeledTree::SubTree(children) if !children.is_empty() => {
            let mut subtree_digests = BTreeMap::new();
            for (label, subtree) in children.iter() {
                curr_path.push(label.to_owned());
                let subwitness = find_subwitness_node(label, witness);
                if let Some(subwitness) = subwitness {
                    let subtree_digest = recompute_digest_impl(subtree, subwitness, curr_path)?;
                    subtree_digests.insert(label.to_owned(), subtree_digest);
                    curr_path.pop();
                } else {
                    return Err(TreeHashError::InconsistentPartialTree {
                        offending_path: curr_path.to_owned(),
                    });
                };
            }
            compute_subtree_digest(witness, &subtree_digests, curr_path)
        }
        _ => unreachable!(),
    }
}

/// Computes and returns a digest for (partial) data given in
/// `partial_tree`, using information from `witness` to compensate for
/// the missing data in the tree. If `partial_tree` is inconsistent with
/// 'witness', i.e. if `witness` does not contain enough information for
/// digest-computation, an error is returned.
///
/// Does not `panic!`.
#[allow(dead_code)]
pub fn recompute_digest(
    partial_tree: &LabeledTree<Vec<u8>>,
    witness: &Witness,
) -> Result<Digest, TreeHashError> {
    let mut curr_path = Vec::new();
    recompute_digest_impl(partial_tree, witness, &mut curr_path)
}

#[derive(PartialEq, Eq, Clone)]
pub struct WitnessGeneratorImpl {
    orig_tree: LabeledTree<Digest>,
    hash_tree: HashTree,
}

fn smallest_label(hash_tree: &HashTree) -> Label {
    let mut smallest = hash_tree;
    while let HashTree::Fork { left_tree, .. } = smallest {
        smallest = left_tree.as_ref()
    }
    match smallest {
        HashTree::Node { label, .. } => label.to_owned(),
        _ => panic!("Inconsistent HashTree, expected HashTree::Node"),
    }
}

fn largest_label(hash_tree: &HashTree) -> Label {
    let mut largest = hash_tree;
    while let HashTree::Fork { right_tree, .. } = largest {
        largest = right_tree.as_ref()
    }
    match largest {
        HashTree::Node { label, .. } => label.to_owned(),
        _ => panic!("Inconsistent HashTree, expected HashTree::Node"),
    }
}

fn largest_witness_label(witness: &Witness) -> Option<Label> {
    match witness {
        Witness::Fork {
            right_tree,
            left_tree,
        } => {
            largest_witness_label(right_tree).map_or_else(|| largest_witness_label(left_tree), Some)
        }
        Witness::Node { label, .. } => Some(label.to_owned()),
        _ => None,
    }
}

fn any_is_in_range(hash_tree: &HashTree, labels: &[Label]) -> bool {
    let smallest = smallest_label(hash_tree);
    let largest = largest_label(hash_tree);
    labels
        .iter()
        .any(|label| (smallest <= *label) && (*label <= largest))
}

// Checks whether any of `needed_labels` is missing in the given `map`.
// Returns a missing label, if any is indeed missing.
fn find_missing_label(
    needed_labels: &[Label],
    map: &BTreeMap<Label, LabeledTree<Digest>>,
) -> Option<Label> {
    for label in needed_labels {
        if map.get(label) == None {
            return Some(label.to_owned());
        }
    }
    None
}

/// WitnessBuilder abstracts away a specific representation of the witness
/// structure and allows us to use the same algorithm to construct both
/// witnesses that don't contain the data (e.g., for XNet) and the ones that do
/// contain it (e.g., for certified reads).
trait WitnessBuilder {
    type Tree;

    fn make_empty() -> Self::Tree;
    fn make_node(label: Label, subtree: Self::Tree) -> Self::Tree;
    fn make_fork(lhs: Self::Tree, rhs: Self::Tree) -> Self::Tree;
    fn make_leaf(data: &[u8]) -> Self::Tree;
    fn make_pruned(digest: Digest) -> Self::Tree;
}

impl WitnessBuilder for Witness {
    type Tree = Self;

    fn make_empty() -> Self {
        Self::Known()
    }

    fn make_node(label: Label, subtree: Self) -> Self {
        Self::Node {
            label,
            sub_witness: Box::new(subtree),
        }
    }

    fn make_fork(lhs: Self, rhs: Self) -> Self {
        Self::Fork {
            left_tree: Box::new(lhs),
            right_tree: Box::new(rhs),
        }
    }

    fn make_leaf(_data: &[u8]) -> Self {
        Self::Known()
    }

    fn make_pruned(digest: Digest) -> Self {
        Self::Pruned { digest }
    }
}

impl WitnessBuilder for MixedHashTree {
    type Tree = Self;

    fn make_empty() -> Self {
        Self::Empty
    }

    fn make_node(label: Label, subtree: Self) -> Self {
        Self::Labeled(label, Box::new(subtree))
    }

    fn make_fork(lhs: Self, rhs: Self) -> Self {
        Self::Fork(Box::new((lhs, rhs)))
    }

    fn make_leaf(data: &[u8]) -> Self {
        Self::Leaf(data.to_vec())
    }

    fn make_pruned(digest: Digest) -> Self {
        Self::Pruned(digest)
    }
}

// Finds in the given `hash_tree` a HashTree::Node that contains the
// given `target_label`, and returns the corresponding HashTree of that node.
// Assumes that the hash tree actually does contain `target_label`-Node.
//
// TODO(CRP-426) currently the running time is O((log n)^2); make it O(log(n))
//     via binary search on the list of all labels in `hash_tree`.
fn find_subtree_node<'a>(target_label: &Label, hash_tree: &'a HashTree) -> &'a HashTree {
    match hash_tree {
        HashTree::Node {
            label, hash_tree, ..
        } => {
            if target_label == label {
                hash_tree.as_ref()
            } else {
                panic!(
                    "Pre-condition failed, hash tree does not contain the label {}.",
                    target_label
                )
            }
        }
        HashTree::Fork {
            left_tree,
            right_tree,
            ..
        } => {
            let largest_left = largest_label(&left_tree);
            if *target_label <= largest_left {
                find_subtree_node(target_label, left_tree)
            } else {
                find_subtree_node(target_label, right_tree)
            }
        }
        HashTree::Leaf { .. } => panic!(
            "Inconsistent state, unexpectedly reached leaf with {:?}",
            hash_tree
        ),
    }
}

// Finds in the given `witness` a sub-witness corresponding to `target_label`,
// if present.
//
// TODO(CRP-426) currently the running time is O((log n)^2); make it O(log(n))
//     via binary search on the list of all labels in `hash_tree`.
fn find_subwitness_node<'a>(target_label: &Label, witness: &'a Witness) -> Option<&'a Witness> {
    match witness {
        Witness::Node { label, sub_witness } => {
            if target_label == label {
                Some(sub_witness)
            } else {
                None
            }
        }
        Witness::Fork {
            left_tree,
            right_tree,
        } => {
            let largest_left = largest_witness_label(left_tree);
            if largest_left.is_some() && *target_label <= largest_left.unwrap() {
                find_subwitness_node(target_label, left_tree)
            } else {
                find_subwitness_node(target_label, right_tree)
            }
        }
        _ => None,
    }
}

// Generates a witness for a HashTree that represents a single
// LabeledTree::SubTree node, and uses the given sub_witnesses
// for the children of the node (if provided).
fn witness_for_subtree<Builder: WitnessBuilder>(
    hash_tree: &HashTree,
    sub_witnesses: &mut BTreeMap<Label, Builder::Tree>,
) -> Builder::Tree {
    let labels: Vec<Label> = sub_witnesses.keys().cloned().collect();
    if any_is_in_range(hash_tree, &labels) {
        match hash_tree {
            HashTree::Fork {
                // inside HashTree, recurse to subtrees
                left_tree,
                right_tree,
                ..
            } => {
                let left_witness = witness_for_subtree::<Builder>(left_tree, sub_witnesses);
                let right_witness = witness_for_subtree::<Builder>(right_tree, sub_witnesses);
                Builder::make_fork(left_witness, right_witness)
            }
            HashTree::Node {
                // bottom of the HashTree, stop recursion
                digest,
                label,
                ..
            } => {
                if let Some(sub_witness) = sub_witnesses.remove(label) {
                    Builder::make_node(label.to_owned(), sub_witness)
                } else {
                    Builder::make_pruned(digest.to_owned())
                }
            }
            HashTree::Leaf { .. } => panic!("Unexpectedly reached {:?}", hash_tree),
        }
    } else {
        Builder::make_pruned(hash_tree.digest().to_owned())
    }
}

impl WitnessGeneratorImpl {
    fn witness_impl<Builder: WitnessBuilder, T: std::convert::AsRef<[u8]> + Debug>(
        &self,
        partial_tree: &LabeledTree<T>,
        orig_tree: &LabeledTree<Digest>,
        hash_tree: &HashTree,
        curr_path: &mut Vec<Label>,
    ) -> Result<Builder::Tree, TreeHashError> {
        match partial_tree {
            LabeledTree::SubTree(children) if children.is_empty() => {
                // An empty SubTree-node in partial tree is allowed only if
                // the corresponding node in the original tree is also empty.
                match orig_tree {
                    LabeledTree::SubTree(orig_children) => {
                        if orig_children.is_empty() {
                            Ok(Builder::make_empty())
                        } else {
                            Err(TreeHashError::InconsistentPartialTree {
                                offending_path: curr_path.to_owned(),
                            })
                        }
                    }
                    _ => Err(TreeHashError::InconsistentPartialTree {
                        offending_path: curr_path.to_owned(),
                    }),
                }
            }
            LabeledTree::SubTree(children) if !children.is_empty() => {
                if let LabeledTree::SubTree(orig_children) = orig_tree {
                    let needed_labels: Vec<Label> = children.keys().cloned().collect();
                    if let Some(missing_label) = find_missing_label(&needed_labels, orig_children) {
                        curr_path.push(missing_label);
                        return Err(TreeHashError::InconsistentPartialTree {
                            offending_path: curr_path.to_owned(),
                        });
                    }
                    // Recursively generate sub-witnesses for each child
                    // of the current LabeledTree::SubTree.
                    // TODO(CRP-426) remove the multiple traversal of the subtree-HashTree
                    //   (in find_subtree_node() and in witness_for_subtree()).
                    let mut sub_witnesses = BTreeMap::new();
                    for label in children.keys() {
                        curr_path.push(label.to_owned());
                        let sub_witness = self.witness_impl::<Builder, _>(
                            children.get(label).unwrap(),
                            orig_children.get(label).unwrap(),
                            find_subtree_node(label, hash_tree),
                            curr_path,
                        )?;
                        curr_path.pop();
                        sub_witnesses.insert(label.to_owned(), sub_witness);
                    }

                    // `children` is a subset of `orig_children`
                    Ok(witness_for_subtree::<Builder>(
                        hash_tree,
                        &mut sub_witnesses,
                    ))
                } else {
                    Err(TreeHashError::InconsistentPartialTree {
                        offending_path: curr_path.to_owned(),
                    })
                }
            }
            LabeledTree::SubTree(_) => unreachable!(),
            LabeledTree::Leaf(data) => match orig_tree {
                LabeledTree::Leaf(_) => Ok(Builder::make_leaf(data.as_ref())),
                _ => panic!(
                    "inconsistent structures, not a leaf in the original labeled tree. \n\
                    partial tree: {:?}\ncurr_path: {:?}",
                    partial_tree, curr_path
                ),
            },
        }
    }
}

impl fmt::Debug for WitnessGeneratorImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "***** labeled tree:")?;
        write_labeled_tree(&self.orig_tree, 0, f)?;
        writeln!(f, "***** hash tree:")?;
        write_hash_tree(&self.hash_tree, 0, f)
    }
}

fn path_as_string(path: &[Label]) -> String {
    let mut str = String::new();
    str.push_str("[");
    for label in path {
        str.push_str(&label.to_string())
    }
    str.push_str("]");
    str
}

// If 'labeled_tree` is a LabeledTree::SubTree with an non-empty map,
// returns this map, and otherwise returns an error.
fn maybe_nonempty_map(
    labeled_tree: LabeledTree<Digest>,
    curr_path: &[Label],
) -> Result<BTreeMap<Label, LabeledTree<Digest>>, TreeHashError> {
    match labeled_tree {
        LabeledTree::Leaf(_) => Err(TreeHashError::InvalidArgument {
            info: "subtree leaf without a node at path ".to_owned() + &path_as_string(curr_path),
        }),
        LabeledTree::SubTree(map) => {
            if map.is_empty() {
                // This is actually not reachable from within `labeled_tree_from_hashtree()`,
                // as before we could create from `HashTree` a `LabeledTree::SubTree`
                // with an empty map, we would encounter the other error case in this match,
                // namely `LabeledTree::Leaf()` with the error "subtree leaf without a node".
                Err(TreeHashError::InvalidArgument {
                    info: "subtree without labels at path ".to_owned() + &path_as_string(curr_path),
                })
            } else {
                Ok(map)
            }
        }
    }
}

#[allow(clippy::map_entry)]
fn labeled_tree_from_hashtree(
    hash_tree: &HashTree,
    curr_path: &mut Vec<Label>,
) -> Result<LabeledTree<Digest>, TreeHashError> {
    match hash_tree {
        HashTree::Leaf { digest } => {
            if *digest == empty_subtree_hash() {
                Ok(LabeledTree::SubTree(BTreeMap::new()))
            } else {
                Ok(LabeledTree::Leaf(digest.to_owned()))
            }
        }
        HashTree::Node {
            label,
            hash_tree: hash_subtree,
            ..
        } => {
            curr_path.push(label.to_owned());
            let labeled_subtree = labeled_tree_from_hashtree(hash_subtree, curr_path)?;
            curr_path.pop();
            let mut map = BTreeMap::new();
            map.insert(label.to_owned(), labeled_subtree);
            Ok(LabeledTree::SubTree(map))
        }

        HashTree::Fork {
            left_tree,
            right_tree,
            ..
        } => {
            let mut map = labeled_tree_from_hashtree(left_tree, curr_path)
                .and_then(|labeled_tree| maybe_nonempty_map(labeled_tree, curr_path))?;

            let right_map = labeled_tree_from_hashtree(right_tree, curr_path)
                .and_then(|labeled_tree| maybe_nonempty_map(labeled_tree, curr_path))?;
            let max_left_label = map.keys().last().unwrap().to_owned();
            for (label, subtree) in right_map {
                if label <= max_left_label {
                    return Err(TreeHashError::InvalidArgument {
                        info: "non-sorted labels in a subtree at path ".to_owned()
                            + &path_as_string(curr_path),
                    });
                } else {
                    map.insert(label, subtree);
                }
            }
            Ok(LabeledTree::SubTree(map))
        }
    }
}

/// Converts a list of `Path`s into a sparse `LabeledTree`.
///
/// The produced `LabeledTree` is considered "sparse" because, if one path is a
/// prefix of another, then only the prefix is returned.
///
/// Example:
///
/// ```text
///     paths = [
///         ["a", "b"],
///         ["a", "c"],
///     ];
///
///               |
///               a
///              /  \
///             b    c
/// ```
///
/// Example (two paths, one is a prefix of the other):
///
/// ```text
///     paths = [
///         ["a", "b"],
///         ["a", "b", "c"],
///     ]
///
///               |
///               a
///              /
///             b
/// ```
pub fn sparse_labeled_tree_from_paths(mut paths: Vec<Path>) -> LabeledTree<()> {
    // Sort all the paths. That way, if one path is a prefix of another, the prefix
    // is always first.
    paths.sort();

    let mut root = LabeledTree::SubTree(BTreeMap::new());

    for path in paths.iter() {
        let mut tree = &mut root;
        for (i, label) in path.iter().enumerate() {
            match tree {
                LabeledTree::Leaf(()) => {
                    // We reached a leaf. That means there was a shared prefix in the paths.
                    // Stop now.
                    break;
                }
                LabeledTree::SubTree(map) => {
                    if !map.contains_key(label) {
                        if i < path.len() - 1 {
                            // Add a subtree for the label on the path.
                            map.insert(label.clone(), LabeledTree::SubTree(BTreeMap::new()));
                        } else {
                            // The last label on the path is always a leaf.
                            map.insert(label.clone(), LabeledTree::Leaf(()));
                        }
                    }
                    // Traverse to the newly created tree.
                    tree = map.get_mut(label).unwrap();
                }
            }
        }
    }

    if root == LabeledTree::SubTree(BTreeMap::new()) {
        root = LabeledTree::Leaf(())
    }

    root
}

impl TryFrom<HashTree> for WitnessGeneratorImpl {
    type Error = TreeHashError;

    /// Creates a `WitnessGenerator` from a `HashTree`, that must have
    /// a structure matching a valid `LabeledTree`.
    /// Returns an error if the given hash tree doesn't match a valid
    /// `LabeledTree`, e.g. if the hash tree has only some `HashTree::Fork`-
    /// and `HashTree::Leaf`-elements, but none `HashTree::Node`-elements.
    fn try_from(hash_tree: HashTree) -> Result<Self, Self::Error> {
        let mut curr_path = Vec::new();
        let labeled_tree = labeled_tree_from_hashtree(&hash_tree, &mut curr_path)?;
        Ok(WitnessGeneratorImpl {
            orig_tree: labeled_tree,
            hash_tree,
        })
    }
}

impl WitnessGenerator for WitnessGeneratorImpl {
    fn hash_tree(&self) -> &HashTree {
        &self.hash_tree
    }

    fn witness(&self, partial_tree: &LabeledTree<Vec<u8>>) -> Result<Witness, TreeHashError> {
        let mut path = Vec::new();
        self.witness_impl::<Witness, _>(partial_tree, &self.orig_tree, &self.hash_tree, &mut path)
    }

    fn mixed_hash_tree(
        &self,
        partial_tree: &LabeledTree<Vec<u8>>,
    ) -> Result<MixedHashTree, TreeHashError> {
        let mut path = Vec::new();
        self.witness_impl::<MixedHashTree, _>(
            partial_tree,
            &self.orig_tree,
            &self.hash_tree,
            &mut path,
        )
    }
}

// Internal state of HashTreeBuilder.
// ActiveNode corresponds to a single node that is under construction, and an
// intermediate state of the builder consists of a vector of ActiveNodes, that
// correspond to the path from the root to the current node under construction.
// Each variant of ActiveNode holds a label, which corresponds to the edge from
// the parent of the node to this ActiveNode.  This label will be then used
// in the constructed LabeledTree.
enum ActiveNode {
    Leaf {
        hasher: Hasher,
        label: Label,
    },
    SubTree {
        children: BTreeMap<Label, LabeledTree<Digest>>,
        label: Label,
        hash_nodes: BTreeMap<Label, HashTree>,
    },
    Undefined {
        label: Label,
    },
}

pub struct HashTreeBuilderImpl {
    labeled_tree: Option<LabeledTree<Digest>>,
    hash_tree: Option<HashTree>,
    curr_path: Vec<ActiveNode>,
}

impl Default for HashTreeBuilderImpl {
    fn default() -> Self {
        Self {
            labeled_tree: None,
            hash_tree: None,
            curr_path: vec![ActiveNode::Undefined {
                label: Label::from("ROOT"),
            }],
        }
    }
}

impl HashTreeBuilderImpl {
    pub fn new() -> Self {
        Self::default()
    }

    // /////////////////////////////////////////////////////////
    // API for obtaining the constructed structures.

    // Returns the HashTree corresponding to the constructed LabeledTree
    // if the construction is complete, and `None` otherwise.
    // Does not `panic!`.
    #[allow(dead_code)]
    pub fn as_hash_tree(&self) -> Option<HashTree> {
        if let Some(hash_tree) = self.hash_tree.as_ref() {
            Some((*hash_tree).to_owned())
        } else {
            None
        }
    }

    // Returns the constructed LabeledTree if the construction
    // is complete, and `None` otherwise.
    // Does not `panic!`.
    #[allow(dead_code)]
    pub fn as_labeled_tree(&self) -> Option<LabeledTree<Digest>> {
        if let Some(labeled_tree) = self.labeled_tree.as_ref() {
            Some(labeled_tree.to_owned())
        } else {
            None
        }
    }
}

impl fmt::Debug for HashTreeBuilderImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "***** aux_state: ")?;
        for (pos, node) in self.curr_path.iter().enumerate() {
            match node {
                ActiveNode::Undefined { label } => {
                    write!(f, "([{}]: '{}') ", pos, label)?;
                }
                ActiveNode::Leaf { label, .. } => {
                    write!(f, "([{}]: '{}' '[hasher]') ", pos, label)?;
                }
                ActiveNode::SubTree {
                    children, label, ..
                } => {
                    write!(f, "[{}]: {} ", pos, label)?;
                    for child in children {
                        write!(f, " child({}, {:?}) ", child.0.clone(), child.1)?;
                    }
                }
            }
        }
        writeln!(f)?;
        if let Some(tree) = self.labeled_tree.as_ref() {
            writeln!(f, "***** labeled tree:")?;
            write_labeled_tree(tree, 0, f)?;
        }
        if let Some(tree) = self.hash_tree.as_ref() {
            writeln!(f, "***** hash tree:")?;
            write_hash_tree(tree, 0, f)?;
        }
        writeln!(f)
    }
}

impl HashTreeBuilder for HashTreeBuilderImpl {
    type WitnessGenerator = WitnessGeneratorImpl;

    fn start_leaf(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Undefined { label } => {
                self.curr_path.push(ActiveNode::Leaf {
                    hasher: new_leaf_hasher(),
                    label,
                });
            }
            _ => panic!("Invalid operation, expected Undefined-node."),
        }
    }

    fn write_leaf(&mut self, bytes: &[u8]) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Leaf { mut hasher, label } => {
                hasher.update(bytes);
                self.curr_path.push(ActiveNode::Leaf { hasher, label })
            }
            _ => panic!("Invalid operation, expected Leaf-node."),
        }
    }

    fn finish_leaf(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Leaf {
                hasher,
                label: child_label,
            } => {
                let digest = hasher.finalize();
                if self.curr_path.is_empty() {
                    // At root.
                    self.labeled_tree = Some(LabeledTree::Leaf(digest.to_owned()));
                    self.hash_tree = Some(HashTree::Leaf { digest });
                } else {
                    // In a subtree.
                    match self.curr_path.pop().unwrap() {
                        ActiveNode::SubTree {
                            mut children,
                            label,
                            mut hash_nodes,
                        } => {
                            children.insert(
                                child_label.to_owned(),
                                LabeledTree::Leaf(digest.to_owned()),
                            );
                            let hash_node = into_hash_node(&child_label, HashTree::Leaf { digest });
                            hash_nodes.insert(child_label, hash_node);
                            self.curr_path.push(ActiveNode::SubTree {
                                children,
                                label,
                                hash_nodes,
                            });
                        }
                        _ => panic!("Invalid state, expected SubTree-node."),
                    }
                }
            }
            _ => panic!("Invalid operation, expected Leaf-node."),
        }
    }

    fn start_subtree(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::Undefined { label } => {
                self.curr_path.push(ActiveNode::SubTree {
                    children: BTreeMap::new(),
                    label,
                    hash_nodes: BTreeMap::new(),
                });
            }
            _ => panic!("Invalid operation, expected Undefined-node."),
        }
    }

    fn new_edge(&mut self, edge_label: Label) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::SubTree {
                children,
                label,
                hash_nodes,
            } => {
                if children.contains_key(&edge_label) {
                    panic!("Edge with label {} already exists.", edge_label);
                }
                self.curr_path.push(ActiveNode::SubTree {
                    children,
                    label,
                    hash_nodes,
                });
                self.curr_path
                    .push(ActiveNode::Undefined { label: edge_label });
            }
            _ => panic!("Invalid operation, expected SubTree-node."),
        }
    }

    fn finish_subtree(&mut self) {
        let head = self.curr_path.pop().expect("Construction completed.");
        match head {
            ActiveNode::SubTree {
                children: finished_children,
                label: finished_label,
                hash_nodes: mut finished_hash_nodes,
            } => {
                let labels: Vec<Label> = finished_hash_nodes.keys().cloned().collect();
                let hash_trees: VecDeque<HashTree> = labels
                    .iter()
                    .map(|label| finished_hash_nodes.remove(label).unwrap())
                    .collect();
                let hash_tree = into_hash_tree(hash_trees);

                if self.curr_path.is_empty() {
                    // At root.
                    self.labeled_tree = Some(LabeledTree::SubTree(finished_children));
                    self.hash_tree = Some(hash_tree);
                } else {
                    // In a subtree.
                    match self.curr_path.pop().unwrap() {
                        ActiveNode::SubTree {
                            mut children,
                            label,
                            mut hash_nodes,
                        } => {
                            children.insert(
                                finished_label.to_owned(),
                                LabeledTree::SubTree(finished_children),
                            );
                            let hash_node = into_hash_node(&finished_label, hash_tree);
                            hash_nodes.insert(finished_label, hash_node);

                            self.curr_path.push(ActiveNode::SubTree {
                                children,
                                label,
                                hash_nodes,
                            });
                        }
                        _ => panic!("Invalid state, expected SubTree-node."),
                    }
                }
            }
            _ => panic!("Invalid operation, expected SubTree-node."),
        }
    }

    fn witness_generator(&self) -> Option<Self::WitnessGenerator> {
        self.as_labeled_tree()
            .map(|orig_tree| WitnessGeneratorImpl {
                orig_tree,
                hash_tree: self.as_hash_tree().unwrap(),
            })
    }
}
