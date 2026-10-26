//! Initialized response models only; no actual namespace proof is minted.
use super::*;
fn complete() -> NamespaceObservation {
    let mut result = NamespaceObservation::default();
    result.started = true;
    result.complete = true;
    let identity = NativeNamespaceIdentity {
        device: 7,
        inode: 900,
    };
    result.identity = Some(identity);
    for read in &mut result.reads {
        let zero = Some(Request {
            result: 0,
            errno: None,
        });
        read.proc_open = Some(Request {
            result: 11,
            errno: None,
        });
        read.task_open = Some(Request {
            result: 12,
            errno: None,
        });
        read.namespace_open = Some(Request {
            result: 13,
            errno: None,
        });
        read.proc_fs_request = zero;
        read.namespace_fs_request = zero;
        read.namespace_stat_request = zero;
        read.namespace_type = Some(Request {
            result: libc::CLONE_NEWPID as libc::c_long,
            errno: None,
        });
        read.proc_fs.f_type = libc::PROC_SUPER_MAGIC as libc::__fsword_t;
        read.namespace_fs.f_type = NSFS_MAGIC;
        read.namespace_stat.st_dev = identity.device;
        read.namespace_stat.st_ino = identity.inode;
        read.identity = Some(identity);
    }
    result
}
#[test]
fn namespace_evidence_requires_all_three_actual_object_identities() {
    assert_eq!(
        complete().validated_identity().unwrap(),
        NativeNamespaceIdentity {
            device: 7,
            inode: 900
        }
    );
    for index in 0..3 {
        for change in 0..4 {
            let mut record = complete();
            match change {
                0 => record.reads[index].identity = None,
                1 => record.reads[index].identity.as_mut().unwrap().inode += 1,
                2 => record.reads[index].namespace_stat.st_dev += 1,
                3 => record.reads[index].namespace_stat.st_ino += 1,
                _ => unreachable!(),
            }
            assert!(
                record.validated_identity().is_err(),
                "accepted object {index} change {change}"
            );
        }
    }
}
#[test]
fn namespace_evidence_rejects_each_missing_or_failed_native_outcome() {
    for index in 0..3 {
        for family in 0..7 {
            for request in [
                None,
                Some(Request {
                    result: -1,
                    errno: Some(libc::EIO),
                }),
                Some(Request {
                    result: 0,
                    errno: Some(libc::EACCES),
                }),
            ] {
                let mut record = complete();
                let read = &mut record.reads[index];
                let target = match family {
                    0 => &mut read.proc_open,
                    1 => &mut read.task_open,
                    2 => &mut read.namespace_open,
                    3 => &mut read.proc_fs_request,
                    4 => &mut read.namespace_fs_request,
                    5 => &mut read.namespace_stat_request,
                    6 => &mut read.namespace_type,
                    _ => unreachable!(),
                };
                *target = request;
                assert!(
                    record.validated_identity().is_err(),
                    "accepted object {index} request {family}"
                );
            }
        }
    }
}
#[test]
fn namespace_evidence_rejects_partial_and_wrong_filesystem_or_namespace_type() {
    assert!(
        NamespaceObservation::default()
            .validated_identity()
            .is_err()
    );
    for change in 0..9 {
        let mut record = complete();
        match change {
            0 => record.started = false,
            1 => record.complete = false,
            2 => record.identity = None,
            3 => record.reads[0].proc_fs.f_type = NSFS_MAGIC,
            4 => record.reads[1].namespace_fs.f_type = libc::PROC_SUPER_MAGIC as libc::__fsword_t,
            5 => {
                record.reads[2].namespace_type.as_mut().unwrap().result =
                    libc::CLONE_NEWUSER as libc::c_long
            }
            6 => record.reads[0].proc_fs_request.as_mut().unwrap().result = 1,
            7 => {
                record.reads[1]
                    .namespace_fs_request
                    .as_mut()
                    .unwrap()
                    .result = 1
            }
            8 => {
                record.reads[2]
                    .namespace_stat_request
                    .as_mut()
                    .unwrap()
                    .result = 1
            }
            _ => unreachable!(),
        }
        assert!(
            record.validated_identity().is_err(),
            "accepted namespace mutation {change}"
        );
    }
}
