use canister_test::*;
use dfn_candid::{candid_one, Candid};
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{Block, ICPTs};

#[test]
fn upgrade_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let accounts: Vec<(PrincipalId, ICPTs)> = (1..5)
            .map(|i| (CanisterId::from_u64(i).get(), ICPTs::from_doms(i)))
            .collect();

        let mut ledger = proj
            .cargo_bin("ledger-canister")
            .install_(&r, Candid((CanisterId::from_u64(0), accounts)))
            .await?;

        async fn get_blocks(canister: &Canister<'_>) -> Result<Vec<Block>, String> {
            let mut blocks = Vec::new();
            let z: u64 = 0;
            for n in z..5 {
                let block: Option<Block> = canister.query_("block", candid_one, n).await?;
                blocks.push(block.unwrap());
            }
            Ok(blocks)
        }

        let blocks_before = get_blocks(&ledger).await?;

        ledger.upgrade_to_self_binary(Vec::new()).await?;

        let blocks_after = get_blocks(&ledger).await?;

        assert_eq!(blocks_before, blocks_after);
        Ok(())
    })
}
