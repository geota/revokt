// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! Test oracle over the upstream Rust crates (spec §9.2). Skeleton until the 0.1 oracle issue.

/// Version of the oracle ABI; bumped with every change to an exported function (CONTRIBUTING: oracles are spec'd).
#[no_mangle]
pub extern "C" fn revokt_oracle_abi_version() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    #[test]
    fn abi_version_is_zero_until_the_oracle_lands() {
        assert_eq!(super::revokt_oracle_abi_version(), 0);
    }
}
