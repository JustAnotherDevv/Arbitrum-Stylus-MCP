use poseidon::poseidon2::Poseidon2::hash;

pub fn commitment(private_key: Field, secret: Field) -> Field {
    hash([private_key, secret], 2)
}

pub fn voter_id(root: Field, priv_key: Field, proposal_id: Field) -> Field {
    hash([root, priv_key, proposal_id], 3)
}

pub fn nullifier(voter_id: Field, option: u8) -> Field {
    hash([voter_id, option as Field], 2)
}
