use crate::bytes_range::BytesRange;
use crate::checkpoint::Checkpoint;
use crate::config::CheckpointOptions;
use crate::db_state::{CoreDbState, SsTableId};
use crate::error::SlateDBError;
use crate::error::SlateDBError::CheckpointMissing;
use crate::manifest::Manifest;
use crate::manifest_store::{ManifestStore, StoredManifest};
use crate::paths::PathResolver;
use fail_parallel::{fail_point, FailPointRegistry};
use object_store::path::Path;
use object_store::ObjectStore;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct SourceDatabase<P: Into<Path>> {
    path: P,
    checkpoint: Uuid,
    visible_range: BytesRange,
}

impl<P: Into<Path>> SourceDatabase<P> {
    fn into_path(self) -> SourceDatabase<Path> {
        SourceDatabase {
            path: self.path.into(),
            checkpoint: self.checkpoint,
            visible_range: self.visible_range,
        }
    }
}

fn validate_sources_are_non_overlapping(
    sources: &[SourceDatabase<Path>],
) -> Result<(), SlateDBError> {
    let mut sorted = vec![];
    for (idx, item) in sources.iter().enumerate() {
        sorted.push((idx, item.visible_range.clone()));
    }
    sorted.sort_by_key(|entry| entry.1.clone());
    for idx in 1..sorted.len() {
        let (previous_idx, previous_range) = &sorted[idx - 1];
        let (current_idx, current_range) = &sorted[idx];
        if previous_range.intersect(current_range).is_some() {
            let previous_path = &sources[*previous_idx].path;
            let current_path = &sources[*current_idx].path;
            return Err(SlateDBError::InvalidArgument {
                msg: format!(
                    "Ranges [{:?}] and [{:?}] for databases at [{}] and [{}] are overlapping",
                    previous_range, current_range, previous_path, current_path
                ),
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) async fn create_multi_clone<P: Into<Path>>(
    clone_path: P,
    sources: Vec<SourceDatabase<P>>,
    object_store: Arc<dyn ObjectStore>,
) -> Result<(), SlateDBError> {
    let sources: Vec<SourceDatabase<Path>> = sources.into_iter().map(|s| s.into_path()).collect();
    validate_sources_are_non_overlapping(&sources)?;

    let clone_path = clone_path.into();
    let mut projected_manifests = vec![];

    for source in sources {
        if clone_path == source.path {
            return Err(SlateDBError::InvalidArgument {
                msg: format!(
                    "Source path '{}' must be different from the clone's path '{}'",
                    source.path, clone_path
                ),
            });
        }

        let final_checkpoint_id = Uuid::new_v4();
        let source_manifest_store =
            Arc::new(ManifestStore::new(&source.path, object_store.clone()));
        let (source_latest_manifest_id, source_latest_manifest) =
            source_manifest_store.read_latest_manifest().await?;
        let Some(source_checkpoint) = source_latest_manifest
            .core
            .find_checkpoint(&source.checkpoint)
        else {
            return Err(CheckpointMissing(source.checkpoint));
        };
        let source_manifest_at_checkpoint =
            if source_checkpoint.manifest_id == source_latest_manifest_id {
                &source_latest_manifest
            } else {
                &source_manifest_store
                    .read_manifest(source_checkpoint.manifest_id)
                    .await?
            };

        if source_manifest_at_checkpoint.core.next_wal_sst_id - 1
            > source_manifest_at_checkpoint.core.last_compacted_wal_sst_id
        {
            return Err(SlateDBError::InvalidArgument {
                msg: format!("Source database at '{}' must have no WAL", source.path),
            });
        }

        let manifest = Manifest::cloned(
            source.path.to_string(),
            source_checkpoint.id,
            final_checkpoint_id,
            source_manifest_at_checkpoint,
        );

        projected_manifests.push(Manifest::projected(&manifest, source.visible_range));
    }

    let merged_manifest = Manifest::merged(projected_manifests);
    let clone_manifest_store = Arc::new(ManifestStore::new(&clone_path, object_store.clone()));
    StoredManifest::init(clone_manifest_store, merged_manifest).await?;

    Ok(())
}

pub(crate) async fn create_clone<P: Into<Path>>(
    clone_path: P,
    parent_path: P,
    object_store: Arc<dyn ObjectStore>,
    parent_checkpoint: Option<Uuid>,
    fp_registry: Arc<FailPointRegistry>,
) -> Result<(), SlateDBError> {
    let clone_path = clone_path.into();
    let parent_path = parent_path.into();

    if clone_path == parent_path {
        return Err(SlateDBError::InvalidArgument {
            msg: format!(
                "Parent path '{}' must be different from the clone's path '{}'",
                parent_path, clone_path
            ),
        });
    }

    let clone_manifest_store = Arc::new(ManifestStore::new(&clone_path, object_store.clone()));
    let parent_manifest_store = Arc::new(ManifestStore::new(&parent_path, object_store.clone()));

    let mut clone_manifest = create_clone_manifest(
        clone_manifest_store,
        parent_manifest_store,
        parent_path.to_string(),
        parent_checkpoint,
        object_store.clone(),
    )
    .await?;

    if !clone_manifest.db_state().initialized {
        copy_wal_ssts(
            object_store,
            clone_manifest.db_state(),
            &parent_path,
            &clone_path,
            fp_registry,
        )
        .await?;

        let mut initialized_db_state = clone_manifest.db_state().clone();
        initialized_db_state.initialized = true;
        clone_manifest.update_db_state(initialized_db_state).await?;
    }

    Ok(())
}

async fn create_clone_manifest(
    clone_manifest_store: Arc<ManifestStore>,
    parent_manifest_store: Arc<ManifestStore>,
    parent_path: String,
    parent_checkpoint_id: Option<Uuid>,
    object_store: Arc<dyn ObjectStore>,
) -> Result<StoredManifest, SlateDBError> {
    let clone_manifest = match StoredManifest::try_load(clone_manifest_store.clone()).await? {
        Some(initialized_clone_manifest) if initialized_clone_manifest.db_state().initialized => {
            validate_attached_to_parent(
                parent_path.clone(),
                parent_checkpoint_id,
                &initialized_clone_manifest,
            )?;
            validate_external_dbs_contain_final_checkpoint(
                parent_manifest_store,
                parent_path.clone(),
                &initialized_clone_manifest,
                object_store.clone(),
            )
            .await?;
            return Ok(initialized_clone_manifest);
        }
        Some(uninitialized_clone_manifest) => {
            validate_attached_to_parent(
                parent_path.clone(),
                parent_checkpoint_id,
                &uninitialized_clone_manifest,
            )?;
            uninitialized_clone_manifest
        }
        None => {
            let mut parent_manifest =
                load_initialized_manifest(parent_manifest_store.clone()).await?;
            let parent_checkpoint =
                get_or_create_parent_checkpoint(&mut parent_manifest, parent_checkpoint_id).await?;
            let parent_manifest_at_checkpoint = parent_manifest_store
                .read_manifest(parent_checkpoint.manifest_id)
                .await?;

            let final_checkpoint_id = Uuid::new_v4();
            StoredManifest::create_uninitialized_clone(
                clone_manifest_store,
                parent_path.clone(),
                parent_checkpoint.id,
                final_checkpoint_id,
                &parent_manifest_at_checkpoint,
            )
            .await?
        }
    };

    // Ensure all external databases contain the final checkpoint.
    for external_db in &clone_manifest.manifest().external_dbs {
        let external_db_manifest_store = if external_db.path == parent_path {
            parent_manifest_store.clone()
        } else {
            Arc::new(ManifestStore::new(
                &external_db.path.clone().into(),
                object_store.clone(),
            ))
        };
        let mut external_db_manifest =
            load_initialized_manifest(external_db_manifest_store).await?;
        if external_db_manifest
            .db_state()
            .find_checkpoint(&external_db.final_checkpoint_id)
            .is_none()
        {
            external_db_manifest
                .write_checkpoint(
                    Some(external_db.final_checkpoint_id),
                    &CheckpointOptions {
                        lifetime: None,
                        source: Some(external_db.source_checkpoint_id),
                    },
                )
                .await?;
        }
    }

    Ok(clone_manifest)
}

// Get a checkpoint and the corresponding manifest that will be used as the source
// for the clone's initial state.
//
// If `parent_checkpoint_id` is `None`, then create an ephemeral checkpoint from
// the latest state.  Making it ephemeral ensures that it will
// get cleaned up if the clone operation fails.
async fn get_or_create_parent_checkpoint(
    manifest: &mut StoredManifest,
    maybe_checkpoint_id: Option<Uuid>,
) -> Result<Checkpoint, SlateDBError> {
    let checkpoint = match maybe_checkpoint_id {
        Some(checkpoint_id) => match manifest.db_state().find_checkpoint(&checkpoint_id) {
            Some(found_checkpoint) => found_checkpoint.clone(),
            None => return Err(CheckpointMissing(checkpoint_id)),
        },
        None => {
            manifest
                .write_checkpoint(
                    None,
                    &CheckpointOptions {
                        lifetime: Some(Duration::from_secs(300)),
                        source: None,
                    },
                )
                .await?
        }
    };
    Ok(checkpoint)
}

// For pre-existing manifests, we need to verify that the referenced checkpoint
// is valid and consistent with the arguments passed to `create_clone`. This
// function returns true if the checkpoint in the clone manifest is still valid
// and false if we should retry checkpoint creation. For other errors, such as
// an inconsistent `DbParent` path, return an error.

fn validate_attached_to_parent(
    parent_path: String,
    parent_checkpoint_id: Option<Uuid>,
    clone_manifest: &StoredManifest,
) -> Result<(), SlateDBError> {
    let external_dbs = &clone_manifest.manifest().external_dbs;
    if external_dbs.is_empty() {
        return Err(SlateDBError::DatabaseAlreadyExists {
            msg: "Database exists, but is not attached to any external database".to_string(),
        });
    }
    if !external_dbs.iter().any(|external_db| {
        parent_path == external_db.path
            && parent_checkpoint_id
                .map(|id| id == external_db.source_checkpoint_id)
                .unwrap_or(true)
    }) {
        return Err(SlateDBError::DatabaseAlreadyExists {
            msg: format!(
                "Database exists, but is not attached to expected external database at [{}] with checkpoint [{}]",
                parent_path,
                parent_checkpoint_id.map(|id| id.to_string()).unwrap_or("<any>".to_string()),
            ),
        });
    };
    Ok(())
}

async fn validate_external_dbs_contain_final_checkpoint(
    parent_manifest_store: Arc<ManifestStore>,
    parent_path: String,
    clone_manifest: &StoredManifest,
    object_store: Arc<dyn ObjectStore>,
) -> Result<(), SlateDBError> {
    // Validate external dbs all contain the final checkpoint
    for external_db in &clone_manifest.manifest().external_dbs {
        let external_manifest_store = if external_db.path == parent_path {
            parent_manifest_store.clone()
        } else {
            Arc::new(ManifestStore::new(
                &external_db.path.clone().into(),
                object_store.clone(),
            ))
        };
        let external_manifest = external_manifest_store.read_latest_manifest().await?.1;
        if external_manifest
            .core
            .find_checkpoint(&external_db.final_checkpoint_id)
            .is_none()
        {
            return Err(SlateDBError::DatabaseAlreadyExists {
                msg: format!(
                    "Cloned database already exists and is initialized, but the final checkpoint [{}] \
                        referred to in the manifest no longer exists in the external database at \
                        path [{}]",
                    external_db.final_checkpoint_id, external_db.path,
                ),
            });
        }
    }

    Ok(())
}

async fn load_initialized_manifest(
    manifest_store: Arc<ManifestStore>,
) -> Result<StoredManifest, SlateDBError> {
    let Some(manifest) = StoredManifest::try_load(manifest_store.clone()).await? else {
        return Err(SlateDBError::LatestManifestMissing);
    };

    if !manifest.db_state().initialized {
        return Err(SlateDBError::InvalidDBState);
    }

    Ok(manifest)
}

async fn copy_wal_ssts(
    object_store: Arc<dyn ObjectStore>,
    parent_checkpoint_state: &CoreDbState,
    parent_path: &Path,
    clone_path: &Path,
    #[allow(unused)] fp_registry: Arc<FailPointRegistry>,
) -> Result<(), SlateDBError> {
    let parent_path_resolver = PathResolver::new(parent_path.clone());
    let clone_path_resolver = PathResolver::new(clone_path.clone());

    let mut wal_id = parent_checkpoint_state.last_compacted_wal_sst_id + 1;
    while wal_id < parent_checkpoint_state.next_wal_sst_id {
        fail_point!(Arc::clone(&fp_registry), "copy-wal-ssts-io-error", |_| Err(
            SlateDBError::from(std::io::Error::new(std::io::ErrorKind::Other, "oops"))
        ));

        let id = SsTableId::Wal(wal_id);
        let parent_path = parent_path_resolver.table_path(&id);
        let clone_path = clone_path_resolver.table_path(&id);
        object_store
            .as_ref()
            .copy(&parent_path, &clone_path)
            .await?;
        wal_id += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::bytes_range::BytesRange;
    use crate::clone::create_clone;
    use crate::config::{CheckpointOptions, CheckpointScope, DbOptions};
    use crate::db::Db;
    use crate::db_state::CoreDbState;
    use crate::error::SlateDBError;
    use crate::manifest::Manifest;
    use crate::manifest_store::{ManifestStore, StoredManifest};
    use crate::proptest_util::{rng, sample};
    use crate::test_utils;
    use fail_parallel::FailPointRegistry;
    use object_store::memory::InMemory;
    use object_store::path::Path;
    use object_store::ObjectStore;
    use rand::seq::SliceRandom;
    use rstest::rstest;
    use std::ops::RangeFull;
    use std::sync::Arc;
    use uuid::Uuid;

    use super::{validate_sources_are_non_overlapping, SourceDatabase};

    #[tokio::test]
    async fn should_clone_latest_state_if_no_checkpoint_provided() {
        let mut rng = rng::new_test_rng(None);
        let table = sample::table(&mut rng, 5000, 10);

        let object_store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let parent_path = Path::from("/tmp/test_parent");
        let clone_path = Path::from("/tmp/test_clone");

        let parent_db = Db::open(parent_path.clone(), Arc::clone(&object_store))
            .await
            .unwrap();
        test_utils::seed_database(&parent_db, &table, false)
            .await
            .unwrap();
        parent_db.flush().await.unwrap();
        parent_db.close().await.unwrap();

        create_clone(
            clone_path.clone(),
            parent_path.clone(),
            Arc::clone(&object_store),
            None,
            Arc::new(FailPointRegistry::new()),
        )
        .await
        .unwrap();

        let clone_db = Db::open(clone_path.clone(), Arc::clone(&object_store))
            .await
            .unwrap();
        let mut db_iter = clone_db.scan::<Vec<u8>, RangeFull>(..).await.unwrap();
        test_utils::assert_ranged_db_scan(&table, .., &mut db_iter).await;
        clone_db.close().await.unwrap();
    }

    #[tokio::test]
    async fn should_clone_from_checkpoint_wal_enabled() {
        should_clone_from_checkpoint(DbOptions::default()).await
    }

    #[cfg(feature = "wal_disable")]
    #[tokio::test]
    async fn should_clone_from_checkpoint_wal_disabled() {
        should_clone_from_checkpoint(DbOptions {
            wal_enabled: false,
            ..DbOptions::default()
        })
        .await
    }

    async fn should_clone_from_checkpoint(db_opts: DbOptions) {
        let mut rng = rng::new_test_rng(None);
        let checkpoint_table = sample::table(&mut rng, 5000, 10);
        let post_checkpoint_table = sample::table(&mut rng, 1000, 10);

        let object_store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let parent_path = Path::from("/tmp/test_parent");
        let clone_path = Path::from("/tmp/test_clone");

        let parent_db = Db::open_with_opts(parent_path.clone(), db_opts, Arc::clone(&object_store))
            .await
            .unwrap();
        test_utils::seed_database(&parent_db, &checkpoint_table, false)
            .await
            .unwrap();
        let checkpoint = parent_db
            .create_checkpoint(
                CheckpointScope::All { force_flush: true },
                &CheckpointOptions::default(),
            )
            .await
            .unwrap();

        // Add some more data so that we can be sure that the clone was created
        // from the checkpoint and not the latest state.
        test_utils::seed_database(&parent_db, &post_checkpoint_table, false)
            .await
            .unwrap();
        parent_db.flush().await.unwrap();
        parent_db.close().await.unwrap();

        create_clone(
            clone_path.clone(),
            parent_path.clone(),
            Arc::clone(&object_store),
            Some(checkpoint.id),
            Arc::new(FailPointRegistry::new()),
        )
        .await
        .unwrap();

        let clone_db = Db::open(clone_path.clone(), Arc::clone(&object_store))
            .await
            .unwrap();
        let mut db_iter = clone_db.scan::<Vec<u8>, RangeFull>(..).await.unwrap();
        test_utils::assert_ranged_db_scan(&checkpoint_table, .., &mut db_iter).await;
        clone_db.close().await.unwrap();
    }

    #[tokio::test]
    async fn should_fail_retry_if_uninitialized_checkpoint_is_invalid() {
        let object_store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let parent_path = Path::from("/tmp/test_parent");
        let clone_path = Path::from("/tmp/test_clone");

        // Create the parent with empty state
        let parent_db = Db::open(parent_path.clone(), Arc::clone(&object_store))
            .await
            .unwrap();
        parent_db.close().await.unwrap();

        // Create an uninitialized manifest with an invalid checkpoint id
        let clone_manifest_store =
            Arc::new(ManifestStore::new(&clone_path, Arc::clone(&object_store)));
        let non_existent_source_checkpoint_id = Uuid::new_v4();
        let final_checkpoint_id = Uuid::new_v4();
        StoredManifest::create_uninitialized_clone(
            clone_manifest_store,
            parent_path.to_string(),
            non_existent_source_checkpoint_id,
            final_checkpoint_id,
            &Manifest::initial(CoreDbState::new()),
        )
        .await
        .unwrap();

        // Cloning should reset the checkpoint to a newly generated id
        let err = create_clone(
            clone_path.clone(),
            parent_path.clone(),
            object_store.clone(),
            None,
            Arc::new(FailPointRegistry::new()),
        )
        .await
        .unwrap_err();

        assert!(
            matches!(err, SlateDBError::CheckpointMissing(id) if id == non_existent_source_checkpoint_id)
        );
    }

    #[tokio::test]
    async fn should_fail_retry_if_uninitialized_checkpoint_differs_from_provided() {
        let object_store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let parent_path = Path::from("/tmp/test_parent");
        let clone_path = Path::from("/tmp/test_clone");

        // Create the parent with empty state
        let parent_manifest_store =
            Arc::new(ManifestStore::new(&parent_path, object_store.clone()));
        let mut parent_sm =
            StoredManifest::create_new_db(parent_manifest_store, CoreDbState::new())
                .await
                .unwrap();
        let checkpoint_1 = parent_sm
            .write_checkpoint(None, &CheckpointOptions::default())
            .await
            .unwrap();
        let checkpoint_2 = parent_sm
            .write_checkpoint(None, &CheckpointOptions::default())
            .await
            .unwrap();

        // Create an uninitialized manifest referring to the first checkpoint
        let clone_manifest_store = Arc::new(ManifestStore::new(&clone_path, object_store.clone()));
        let final_checkpoint_id = Uuid::new_v4();
        StoredManifest::create_uninitialized_clone(
            clone_manifest_store,
            parent_path.to_string(),
            checkpoint_1.id,
            final_checkpoint_id,
            &Manifest::initial(CoreDbState::new()),
        )
        .await
        .unwrap();

        // Cloning with the second checkpoint should fail
        let err = create_clone(
            clone_path.clone(),
            parent_path.clone(),
            object_store.clone(),
            Some(checkpoint_2.id),
            Arc::new(FailPointRegistry::new()),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, SlateDBError::DatabaseAlreadyExists { .. }));
    }

    #[tokio::test]
    async fn should_fail_retry_if_parent_path_is_different() {
        let object_store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let original_parent_path = Path::from("/tmp/test_parent");
        let updated_parent_path = Path::from("/tmp/test_parent/new");
        let clone_path = Path::from("/tmp/test_clone");

        // Setup an uninitialized manifest pointing to a different parent
        let parent_manifest = Manifest::initial(CoreDbState::new());
        let clone_manifest_store =
            Arc::new(ManifestStore::new(&clone_path, Arc::clone(&object_store)));
        StoredManifest::create_uninitialized_clone(
            Arc::clone(&clone_manifest_store),
            original_parent_path.to_string(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &parent_manifest,
        )
        .await
        .unwrap();

        // Initialize the parent at the updated path
        let parent_db = Db::open(updated_parent_path.clone(), Arc::clone(&object_store))
            .await
            .unwrap();
        parent_db.close().await.unwrap();

        // The clone should fail because of inconsistent parent information
        let err = create_clone(
            clone_path.clone(),
            updated_parent_path.clone(),
            Arc::clone(&object_store),
            None,
            Arc::new(FailPointRegistry::new()),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            SlateDBError::DatabaseAlreadyExists { msg: _ }
        ));
    }

    #[tokio::test]
    async fn clone_retry_should_be_idempotent_after_success() -> Result<(), SlateDBError> {
        let object_store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let parent_path = "/tmp/test_parent";
        let clone_path = "/tmp/test_clone";

        let parent_db = Db::open(parent_path, Arc::clone(&object_store))
            .await
            .unwrap();
        parent_db.close().await.unwrap();

        create_clone(
            clone_path,
            parent_path,
            Arc::clone(&object_store),
            None,
            Arc::new(FailPointRegistry::new()),
        )
        .await
        .unwrap();

        let clone_manifest_store =
            ManifestStore::new(&Path::from(clone_path), Arc::clone(&object_store));
        let (manifest_id, _) = clone_manifest_store.read_latest_manifest().await.unwrap();

        create_clone(
            clone_path,
            parent_path,
            Arc::clone(&object_store),
            None,
            Arc::new(FailPointRegistry::new()),
        )
        .await?;

        assert_eq!(
            manifest_id,
            clone_manifest_store.read_latest_manifest().await.unwrap().0
        );

        Ok(())
    }

    #[tokio::test]
    async fn should_retry_clone_after_io_error_copying_wals() {
        let fp_registry = Arc::new(FailPointRegistry::new());
        let object_store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let parent_path = Path::from("/tmp/test_parent");
        let clone_path = Path::from("/tmp/test_clone");

        let parent_db = Db::open(parent_path.clone(), Arc::clone(&object_store))
            .await
            .unwrap();
        let mut rng = rng::new_test_rng(None);
        test_utils::seed_database(&parent_db, &sample::table(&mut rng, 100, 10), false)
            .await
            .unwrap();
        parent_db.flush().await.unwrap();

        test_utils::seed_database(&parent_db, &sample::table(&mut rng, 100, 10), false)
            .await
            .unwrap();
        parent_db.flush().await.unwrap();
        parent_db.close().await.unwrap();

        fail_parallel::cfg(
            Arc::clone(&fp_registry),
            "copy-wal-ssts-io-error",
            "1*off->return",
        )
        .unwrap();

        let err = create_clone(
            clone_path.clone(),
            parent_path.clone(),
            Arc::clone(&object_store),
            None,
            Arc::clone(&fp_registry),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SlateDBError::IoError(_)));

        fail_parallel::cfg(Arc::clone(&fp_registry), "copy-wal-ssts-io-error", "off").unwrap();
        create_clone(
            clone_path.clone(),
            parent_path.clone(),
            Arc::clone(&object_store),
            None,
            Arc::clone(&fp_registry),
        )
        .await
        .unwrap();
    }

    struct RangeValidationTestCase {
        ranges: Vec<BytesRange>,
        is_ok: bool,
    }

    #[rstest]
    #[case(RangeValidationTestCase {
        ranges: vec![
            BytesRange::from_ref("a".."b"),
            BytesRange::from_ref("b".."c"),
            BytesRange::from_ref("c".."d"),
        ],
        is_ok: true,
    })]
    #[case(RangeValidationTestCase {
        ranges: vec![
            BytesRange::from_ref("a"..),
            BytesRange::from_ref("b".."c"),
            BytesRange::from_ref("c".."d"),
        ],
        is_ok: false,
    })]
    #[case(RangeValidationTestCase {
        ranges: vec![
            BytesRange::from_ref(.."z"),
            BytesRange::from_ref("a".."b"),
            BytesRange::from_ref("c".."d"),
        ],
        is_ok: false,
    })]
    #[case(RangeValidationTestCase {
        ranges: vec![
            BytesRange::from_ref(.."d"),
            BytesRange::from_ref("d".."z"),
        ],
        is_ok: true,
    })]
    fn test_validate_sources_are_non_overlapping(#[case] test_case: RangeValidationTestCase) {
        let mut shuffled = test_case.ranges.clone();
        shuffled.shuffle(&mut rng::new_test_rng(None));
        let mut sources = vec![];
        for idx in 0..test_case.ranges.len() {
            sources.push(SourceDatabase {
                path: Path::from(format!("/tmp/{}", idx)),
                visible_range: test_case.ranges[idx].clone(),
                checkpoint: Uuid::new_v4(),
            });
        }
        assert_eq!(
            validate_sources_are_non_overlapping(&sources).is_ok(),
            test_case.is_ok
        );
    }
}
