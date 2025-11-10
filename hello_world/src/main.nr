mod definitions;
mod merkle_tree;

use poseidon::poseidon2::Poseidon2::hash;

global DEPTH: u32 = 2;

fn main(
    root: pub Field,
    path: [Field; DEPTH],
    direction_selector: [bool; DEPTH],
    secret: Field,
    priv_key: Field,
    voter_id: pub Field,
    nullifier: pub Field,
    proposal_id: pub Field,
    option: pub u8,
    vote_strength: pub u8,
) {
    let note_commitment = definitions::commitment(priv_key, secret);

    merkle_tree::assert_merkle_inclusion(
        root,
        path,
        direction_selector,
        note_commitment,
        "Commitment not in Merkle Tree",
    );

    assert(voter_id == definitions::voter_id(root, priv_key, proposal_id), "Invalid voter_id");

    assert(nullifier == definitions::nullifier(voter_id, option), "Invalid nullifier");

    assert(vote_strength >= 1, "Must vote at least 1");
    assert(vote_strength <= 10, "Max vote strength is 10");
}

#[test]
fn test_single_option_vote() {
    let priv_key = 123456789;
    let secret = 987654321;
    let proposal_id = 1;
    let option = 0;
    let vote_strength = 5;

    let note_commitment = definitions::commitment(priv_key, secret);

    let sibling = definitions::commitment(0, 0);
    let left_branch = hash([note_commitment, sibling], 2);
    let right_branch = hash([sibling, sibling], 2);
    let root = hash([left_branch, right_branch], 2);

    let path = [sibling, right_branch];
    let direction_selector = [false, false];

    let voter_id = definitions::voter_id(root, priv_key, proposal_id);
    let nullifier = definitions::nullifier(voter_id, option);

    std::println(voter_id);
    std::println(nullifier);

    main(
        root,
        path,
        direction_selector,
        secret,
        priv_key,
        voter_id,
        nullifier,
        proposal_id,
        option,
        vote_strength,
    );
}

#[test]
fn test_multiple_options_same_voter() {
    let priv_key = 555666777;
    let secret = 111222333;
    let proposal_id = 1;

    let note_commitment = definitions::commitment(priv_key, secret);
    let sibling = definitions::commitment(0, 0);
    let left_branch = hash([note_commitment, sibling], 2);
    let right_branch = hash([sibling, sibling], 2);
    let root = hash([left_branch, right_branch], 2);

    let path = [sibling, right_branch];
    let direction_selector = [false, false];
    let voter_id = definitions::voter_id(root, priv_key, proposal_id);

    let nullifier_a = definitions::nullifier(voter_id, 0);
    main(
        root,
        path,
        direction_selector,
        secret,
        priv_key,
        voter_id,
        nullifier_a,
        proposal_id,
        0,
        5,
    );

    let nullifier_b = definitions::nullifier(voter_id, 1);
    main(
        root,
        path,
        direction_selector,
        secret,
        priv_key,
        voter_id,
        nullifier_b,
        proposal_id,
        1,
        3,
    );

    let nullifier_c = definitions::nullifier(voter_id, 2);
    main(
        root,
        path,
        direction_selector,
        secret,
        priv_key,
        voter_id,
        nullifier_c,
        proposal_id,
        2,
        2,
    );
}

#[test(should_fail_with = "Must vote at least 1")]
fn test_invalid_vote_strength() {
    let priv_key = 123456789;
    let secret = 987654321;
    let proposal_id = 1;
    let option = 0;
    let vote_strength = 0;

    let note_commitment = definitions::commitment(priv_key, secret);
    let sibling = definitions::commitment(0, 0);
    let left_branch = hash([note_commitment, sibling], 2);
    let right_branch = hash([sibling, sibling], 2);
    let root = hash([left_branch, right_branch], 2);

    let path = [sibling, right_branch];
    let direction_selector = [false, false];
    let voter_id = definitions::voter_id(root, priv_key, proposal_id);
    let nullifier = definitions::nullifier(voter_id, option);

    main(
        root,
        path,
        direction_selector,
        secret,
        priv_key,
        voter_id,
        nullifier,
        proposal_id,
        option,
        vote_strength,
    );
}

#[test(should_fail_with = "Invalid voter_id")]
fn test_invalid_voter_id() {
    let priv_key = 123456789;
    let secret = 987654321;
    let proposal_id = 1;
    let option = 0;
    let vote_strength = 5;

    let note_commitment = definitions::commitment(priv_key, secret);
    let sibling = definitions::commitment(0, 0);
    let left_branch = hash([note_commitment, sibling], 2);
    let right_branch = hash([sibling, sibling], 2);
    let root = hash([left_branch, right_branch], 2);

    let path = [sibling, right_branch];
    let direction_selector = [false, false];

    let wrong_voter_id = definitions::voter_id(root, priv_key, proposal_id + 1);
    let nullifier = definitions::nullifier(wrong_voter_id, option);

    main(
        root,
        path,
        direction_selector,
        secret,
        priv_key,
        wrong_voter_id,
        nullifier,
        proposal_id,
        option,
        vote_strength,
    );
}

#[test(should_fail_with = "Invalid nullifier")]
fn test_invalid_nullifier() {
    let priv_key = 123456789;
    let secret = 987654321;
    let proposal_id = 1;
    let option = 0;
    let vote_strength = 5;

    let note_commitment = definitions::commitment(priv_key, secret);
    let sibling = definitions::commitment(0, 0);
    let left_branch = hash([note_commitment, sibling], 2);
    let right_branch = hash([sibling, sibling], 2);
    let root = hash([left_branch, right_branch], 2);

    let path = [sibling, right_branch];
    let direction_selector = [false, false];
    let voter_id = definitions::voter_id(root, priv_key, proposal_id);

    let wrong_nullifier = definitions::nullifier(voter_id, option + 1);

    main(
        root,
        path,
        direction_selector,
        secret,
        priv_key,
        voter_id,
        wrong_nullifier,
        proposal_id,
        option,
        vote_strength,
    );
}

#[test]
fn compute_correct_values() {
    let root = 0x100f21ac2567c6855e6c874c50500195e02647da0f1393dae9b634eceb4eb839;
    let priv_key = 0x27d3cc6406e9a819149611eb04df3d1170afc78971040291e98c88dd6ca09aa6;
    let proposal_id = 0x01;
    let option = 0;

    let correct_voter_id = definitions::voter_id(root, priv_key, proposal_id);
    let correct_nullifier = definitions::nullifier(correct_voter_id, option);

    std::println("voter_id:");
    std::println(correct_voter_id);
    std::println("nullifier:");
    std::println(correct_nullifier);

    assert(true);
}
