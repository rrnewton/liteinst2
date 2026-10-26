//! Actual EXEC/EXIT refusal controls for the prospective mapping reservation.
use super::*;

#[test]
fn changed_reserved_census_refuses_before_entry_patch_or_permission_change() {
    for mutation in 0..3 {
        let fixture = Fixture::new(false);
        let mut harness = Harness::new();
        harness.owner().lifecycle_options = Some(DynamicLifecycleOptions::default());
        let ready = harness.launch(&fixture).unwrap();
        let app_handle = pin(ready.pid);
        let helper_handle = pin(harness.owner().broker.as_ref().unwrap().pid);
        let token = ready.event.stop_token().unwrap();
        let before = trusted::TaskStateSnapshot::read(ready.pid).unwrap();
        let maps = read_maps(ready.pid).unwrap();
        let original = read_memory(ready.pid, 0x400000, 8192).unwrap();
        assert_eq!(original[4096..4098], [0xeb, 0xfe]);
        let mut census = harness.owner().admission_mapping_census(token).unwrap();
        let index = census
            .iter()
            .position(|mapping| mapping.start == 0x400000)
            .unwrap();
        match mutation {
            0 => {
                census.remove(index);
            }
            1 => {
                census[index].file_offset += 4096;
            }
            2 => {
                census[index].pathname = Some("substituted-model-image".into());
            }
            _ => unreachable!(),
        }
        // SAFETY: the owned literal fixture has no external writer, alternate
        // entry or code observer. Only the prospective accounting census is
        // corrupted; no native source or stopped-task evidence is forged.
        let result = unsafe {
            harness
                .owner()
                .bootstrap_admission(token, &census, Instant::now() + TIMEOUT)
        };
        assert!(matches!(
            result,
            Err(LaunchError::Invalid(
                "bootstrap executable census changed after its resource reservation"
            ))
        ));
        assert!(harness.owner().closing);
        assert!(harness.owner().cancel.load(Ordering::Acquire));
        let mut expected = before;
        expected.registers.rax = 0;
        assert_eq!(
            trusted::TaskStateSnapshot::read(ready.pid).unwrap(),
            expected
        );
        assert_eq!(read_maps(ready.pid).unwrap(), maps);
        assert_eq!(read_memory(ready.pid, 0x400000, 8192).unwrap(), original);
        let cleanup = harness.finish();
        assert_eq!(cleanup.reaped, [ready.pid]);
        reaped(&app_handle);
        reaped(&helper_handle);
    }
}
