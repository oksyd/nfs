#![cfg(any(feature = "blocking", feature = "tokio"))]

use std::collections::BTreeSet;
use std::env;
#[cfg(feature = "blocking")]
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use nfs::Result;

const LARGE_PAYLOAD_SIZE: usize = 192 * 1024 + 123;
const LARGE_RANGE_OFFSET: usize = 65_537;
const LARGE_RANGE_LEN: usize = 131_099;
const PAGED_DIR_ENTRIES: usize = 24;
const PAGED_DIR_LIMIT: usize = 128;

#[cfg(feature = "blocking")]
#[test]
fn live_v3_blocking_roundtrip_when_configured() -> Result<()> {
    let Some(target) = env_var("NFS_RS_V3_TARGET") else {
        return Ok(());
    };
    let prefix = env::var("NFS_RS_TEST_PREFIX").unwrap_or_else(|_| "/".to_owned());
    let root = unique_path(&prefix, "v3-blocking");

    let mut client = nfs::v3::blocking::Client::connect(&target)?;
    let flow = exercise_v3_blocking(&mut client, &root);
    let cleanup = client.remove_all_if_exists(&root).map(|_| ());
    let unmount = client.unmount();
    finish(flow, cleanup, unmount)
}

#[cfg(feature = "blocking")]
#[test]
fn live_v4_blocking_roundtrip_when_configured() -> Result<()> {
    let Some(host) = env_var("NFS_RS_V4_HOST") else {
        return Ok(());
    };
    let prefix = env::var("NFS_RS_V4_PREFIX")
        .or_else(|_| env::var("NFS_RS_TEST_PREFIX"))
        .unwrap_or_else(|_| "/".to_owned());
    let root = unique_path(&prefix, "v4-blocking");

    let mut client = nfs::v4::blocking::Client::connect(host)?;
    let flow = exercise_v4_blocking(&mut client, &root);
    let cleanup = client.remove_all_if_exists(&root).map(|_| ());
    let shutdown = client.shutdown();
    finish(flow, cleanup, shutdown)
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn live_v3_tokio_roundtrip_when_configured() -> Result<()> {
    let Some(target) = env_var("NFS_RS_V3_TARGET") else {
        return Ok(());
    };
    let prefix = env::var("NFS_RS_TEST_PREFIX").unwrap_or_else(|_| "/".to_owned());
    let root = unique_path(&prefix, "v3-tokio");

    let mut client = nfs::v3::tokio::Client::connect(&target).await?;
    let flow = exercise_v3_tokio(&mut client, &root).await;
    let cleanup = client.remove_all_if_exists(&root).await.map(|_| ());
    let unmount = client.unmount().await;
    finish(flow, cleanup, unmount)
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn live_v4_tokio_roundtrip_when_configured() -> Result<()> {
    let Some(host) = env_var("NFS_RS_V4_HOST") else {
        return Ok(());
    };
    let prefix = env::var("NFS_RS_V4_PREFIX")
        .or_else(|_| env::var("NFS_RS_TEST_PREFIX"))
        .unwrap_or_else(|_| "/".to_owned());
    let root = unique_path(&prefix, "v4-tokio");

    let mut client = nfs::v4::tokio::Client::connect(host).await?;
    let flow = exercise_v4_tokio(&mut client, &root).await;
    let cleanup = client.remove_all_if_exists(&root).await.map(|_| ());
    let shutdown = client.shutdown().await;
    finish(flow, cleanup, shutdown)
}

#[cfg(feature = "blocking")]
fn exercise_v3_blocking(client: &mut nfs::v3::blocking::Client, root: &str) -> Result<()> {
    let file = join_path(root, "payload.txt");
    let renamed = join_path(root, "renamed.txt");
    let created = join_path(root, "created.txt");
    let atomic = join_path(root, "atomic.txt");
    let atomic_streamed = join_path(root, "atomic-streamed.txt");
    let streamed = join_path(root, "streamed.txt");
    let appended = join_path(root, "appended.txt");
    let nested_root = join_path(root, "nested");
    let nested_dir = join_path(&nested_root, "a/b");
    let nested_file = join_path(&nested_dir, "leaf.txt");
    let empty_dir = join_path(root, "empty");

    client.mkdir(root, 0o755)?;
    assert!(client.is_dir(root)?);
    assert!(client.fsinfo().is_some());
    assert!(client.root_fsinfo().is_some());
    client.path_fsinfo(root)?;
    client.fsstat(root)?;
    client.pathconf(root)?;
    client.create_new(&created, 0o644)?;
    assert!(client.is_file(&created)?);
    assert!(client.create_new(&created, 0o644).is_err());
    assert!(client.remove_if_exists(&created)?);
    assert!(!client.remove_if_exists(&created)?);
    client.mkdir(&empty_dir, 0o755)?;
    assert!(client.rmdir_if_exists(&empty_dir)?);
    assert!(!client.rmdir_if_exists(&empty_dir)?);
    client.create_dir_all(&nested_dir, 0o755)?;
    client.write(&nested_file, b"nested")?;
    assert!(client.is_file(&nested_file)?);
    assert_eq!(client.read(&nested_file)?, b"nested");
    assert!(
        client
            .read_dir_limited(&nested_dir, 16)?
            .iter()
            .any(|entry| entry.name == "leaf.txt")
    );
    let page = client.read_dir_page_limited(&nested_dir, None, 16)?;
    assert!(page.entries.iter().any(|entry| entry.name == "leaf.txt"));
    assert!(client.remove_all_if_exists(&nested_root)?);
    assert!(!client.remove_all_if_exists(&nested_root)?);
    assert!(!client.exists(&nested_root)?);
    client.write(&file, b"nfs-rs-live")?;
    client.write_atomic(&atomic, b"atomic")?;
    assert_eq!(client.read(&atomic)?, b"atomic");
    client.write_atomic(&atomic, b"atomic-replaced")?;
    assert_eq!(client.read(&atomic)?, b"atomic-replaced");
    let mut atomic_reader = Cursor::new(&b"atomic-reader"[..]);
    assert_eq!(
        client.write_atomic_from_reader(&atomic_streamed, &mut atomic_reader)?,
        13
    );
    assert_eq!(client.read(&atomic_streamed)?, b"atomic-reader");
    assert!(client.remove_if_exists(&atomic_streamed)?);
    assert!(client.remove_if_exists(&atomic)?);
    let mut reader = Cursor::new(&b"streamed"[..]);
    assert_eq!(client.write_from_reader(&streamed, &mut reader)?, 8);
    assert_eq!(client.read(&streamed)?, b"streamed");
    client.remove(&streamed)?;
    client.write(&appended, b"a")?;
    assert_eq!(client.append(&appended, b"bc")?, 2);
    let mut append_reader = Cursor::new(&b"de"[..]);
    assert_eq!(client.append_from_reader(&appended, &mut append_reader)?, 2);
    assert_eq!(client.read(&appended)?, b"abcde");
    client.remove(&appended)?;
    assert_eq!(client.read(&file)?, b"nfs-rs-live");
    client.set_mode(&file, 0o600)?;
    assert_eq!(client.metadata(&file)?.mode & 0o777, 0o600);
    assert_eq!(client.read_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_exact_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_range(&file, 4, 7)?, b"rs-live");
    let mut range = Vec::new();
    assert_eq!(client.read_range_to_writer(&file, 4, 7, &mut range)?, 7);
    assert_eq!(range, b"rs-live");
    client.write_at(&file, 4, b"RS")?;
    assert_eq!(client.read(&file)?, b"nfs-RS-live");
    client.truncate(&file, 6)?;
    assert_eq!(client.read(&file)?, b"nfs-RS");
    client.commit(&file, 0, 0)?;
    client.rename(&file, &renamed)?;
    assert_eq!(client.read(&renamed)?, b"nfs-RS");
    let copied = join_path(root, "copied.txt");
    let atomic_copied = join_path(root, "atomic-copied.txt");
    assert_eq!(client.copy(&renamed, &copied)?, 6);
    assert_eq!(client.read(&copied)?, b"nfs-RS");
    assert_eq!(client.copy_atomic(&renamed, &atomic_copied)?, 6);
    assert_eq!(client.read(&atomic_copied)?, b"nfs-RS");
    assert!(client.remove_if_exists(&atomic_copied)?);
    assert!(client.remove_if_exists(&copied)?);
    assert!(client.remove_if_exists(&renamed)?);
    exercise_v3_blocking_large_io(client, root)?;
    exercise_v3_blocking_paged_dir(client, root)?;
    client.reconnect()?;
    assert!(client.is_dir(root)?);
    Ok(())
}

#[cfg(feature = "blocking")]
fn exercise_v4_blocking(client: &mut nfs::v4::blocking::Client, root: &str) -> Result<()> {
    let file = join_path(root, "payload.txt");
    let renamed = join_path(root, "renamed.txt");
    let created = join_path(root, "created.txt");
    let atomic = join_path(root, "atomic.txt");
    let atomic_streamed = join_path(root, "atomic-streamed.txt");
    let streamed = join_path(root, "streamed.txt");
    let appended = join_path(root, "appended.txt");
    let nested_root = join_path(root, "nested");
    let nested_dir = join_path(&nested_root, "a/b");
    let nested_file = join_path(&nested_dir, "leaf.txt");
    let empty_dir = join_path(root, "empty");

    client.renew()?;
    client.mkdir(root, 0o755)?;
    assert!(client.is_dir(root)?);
    assert!(client.root_fsinfo().is_some());
    client.fsinfo(root)?;
    client.fsstat(root)?;
    client.pathconf(root)?;
    client.create_new_with_mode(&created, 0o644)?;
    assert!(client.is_file(&created)?);
    assert!(client.create_new(&created).is_err());
    assert!(client.remove_if_exists(&created)?);
    assert!(!client.remove_if_exists(&created)?);
    client.mkdir(&empty_dir, 0o755)?;
    assert!(client.rmdir_if_exists(&empty_dir)?);
    assert!(!client.rmdir_if_exists(&empty_dir)?);
    client.create_dir_all(&nested_dir, 0o755)?;
    client.write(&nested_file, b"nested")?;
    assert!(client.is_file(&nested_file)?);
    assert_eq!(client.read(&nested_file)?, b"nested");
    assert!(
        client
            .read_dir_limited(&nested_dir, 16)?
            .iter()
            .any(|entry| entry.name == "leaf.txt")
    );
    let page = client.read_dir_page_limited(&nested_dir, None, 16)?;
    assert!(page.entries.iter().any(|entry| entry.name == "leaf.txt"));
    assert!(client.remove_all_if_exists(&nested_root)?);
    assert!(!client.remove_all_if_exists(&nested_root)?);
    assert!(!client.exists(&nested_root)?);
    client.write(&file, b"nfs-rs-live")?;
    client.write_atomic(&atomic, b"atomic")?;
    assert_eq!(client.read(&atomic)?, b"atomic");
    client.write_atomic_with_mode(&atomic, b"atomic-replaced", 0o644)?;
    assert_eq!(client.read(&atomic)?, b"atomic-replaced");
    let mut atomic_reader = Cursor::new(&b"atomic-reader"[..]);
    assert_eq!(
        client.write_atomic_from_reader(&atomic_streamed, &mut atomic_reader)?,
        13
    );
    assert_eq!(client.read(&atomic_streamed)?, b"atomic-reader");
    assert!(client.remove_if_exists(&atomic_streamed)?);
    assert!(client.remove_if_exists(&atomic)?);
    let mut reader = Cursor::new(&b"streamed"[..]);
    assert_eq!(client.write_from_reader(&streamed, &mut reader)?, 8);
    assert_eq!(client.read(&streamed)?, b"streamed");
    client.remove(&streamed)?;
    client.write(&appended, b"a")?;
    assert_eq!(client.append(&appended, b"bc")?, 2);
    let mut append_reader = Cursor::new(&b"de"[..]);
    assert_eq!(client.append_from_reader(&appended, &mut append_reader)?, 2);
    assert_eq!(client.read(&appended)?, b"abcde");
    client.remove(&appended)?;
    assert_eq!(client.read(&file)?, b"nfs-rs-live");
    client.set_mode(&file, 0o600)?;
    if let Some(mode) = client.metadata(&file)?.mode {
        assert_eq!(mode & 0o777, 0o600);
    }
    client.setattr(&file, &nfs::v4::SetAttrs::size(4))?;
    assert_eq!(client.read(&file)?, b"nfs-");
    client.write(&file, b"nfs-rs-live")?;
    assert_eq!(client.read_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_exact_at(&file, 4, 2)?, b"rs");
    assert_eq!(client.read_range(&file, 4, 7)?, b"rs-live");
    let mut range = Vec::new();
    assert_eq!(client.read_range_to_writer(&file, 4, 7, &mut range)?, 7);
    assert_eq!(range, b"rs-live");
    client.write_at(&file, 4, b"RS")?;
    assert_eq!(client.read(&file)?, b"nfs-RS-live");
    client.truncate(&file, 6)?;
    assert_eq!(client.read(&file)?, b"nfs-RS");
    client.commit(&file, 0, 0)?;
    client.rename(&file, &renamed)?;
    assert_eq!(client.read(&renamed)?, b"nfs-RS");
    let copied = join_path(root, "copied.txt");
    let atomic_copied = join_path(root, "atomic-copied.txt");
    assert_eq!(client.copy(&renamed, &copied)?, 6);
    assert_eq!(client.read(&copied)?, b"nfs-RS");
    assert_eq!(client.copy_atomic(&renamed, &atomic_copied)?, 6);
    assert_eq!(client.read(&atomic_copied)?, b"nfs-RS");
    assert!(client.remove_if_exists(&atomic_copied)?);
    assert!(client.remove_if_exists(&copied)?);
    assert!(client.remove_if_exists(&renamed)?);
    exercise_v4_blocking_large_io(client, root)?;
    exercise_v4_blocking_paged_dir(client, root)?;
    client.reconnect()?;
    assert!(client.is_dir(root)?);
    Ok(())
}

#[cfg(feature = "tokio")]
async fn exercise_v3_tokio(client: &mut nfs::v3::tokio::Client, root: &str) -> Result<()> {
    let file = join_path(root, "payload.txt");
    let renamed = join_path(root, "renamed.txt");
    let created = join_path(root, "created.txt");
    let atomic = join_path(root, "atomic.txt");
    let atomic_streamed = join_path(root, "atomic-streamed.txt");
    let streamed = join_path(root, "streamed.txt");
    let appended = join_path(root, "appended.txt");
    let nested_root = join_path(root, "nested");
    let nested_dir = join_path(&nested_root, "a/b");
    let nested_file = join_path(&nested_dir, "leaf.txt");
    let empty_dir = join_path(root, "empty");

    client.mkdir(root, 0o755).await?;
    assert!(client.is_dir(root).await?);
    assert!(client.fsinfo().is_some());
    assert!(client.root_fsinfo().is_some());
    client.path_fsinfo(root).await?;
    client.fsstat(root).await?;
    client.pathconf(root).await?;
    client.create_new(&created, 0o644).await?;
    assert!(client.is_file(&created).await?);
    assert!(client.create_new(&created, 0o644).await.is_err());
    assert!(client.remove_if_exists(&created).await?);
    assert!(!client.remove_if_exists(&created).await?);
    client.mkdir(&empty_dir, 0o755).await?;
    assert!(client.rmdir_if_exists(&empty_dir).await?);
    assert!(!client.rmdir_if_exists(&empty_dir).await?);
    client.create_dir_all(&nested_dir, 0o755).await?;
    client.write(&nested_file, b"nested").await?;
    assert!(client.is_file(&nested_file).await?);
    assert_eq!(client.read(&nested_file).await?, b"nested");
    assert!(
        client
            .read_dir_limited(&nested_dir, 16)
            .await?
            .iter()
            .any(|entry| entry.name == "leaf.txt")
    );
    let page = client.read_dir_page_limited(&nested_dir, None, 16).await?;
    assert!(page.entries.iter().any(|entry| entry.name == "leaf.txt"));
    assert!(client.remove_all_if_exists(&nested_root).await?);
    assert!(!client.remove_all_if_exists(&nested_root).await?);
    assert!(!client.exists(&nested_root).await?);
    client.write(&file, b"nfs-rs-live").await?;
    client.write_atomic(&atomic, b"atomic").await?;
    assert_eq!(client.read(&atomic).await?, b"atomic");
    client.write_atomic(&atomic, b"atomic-replaced").await?;
    assert_eq!(client.read(&atomic).await?, b"atomic-replaced");
    let mut atomic_reader = &b"atomic-reader"[..];
    assert_eq!(
        client
            .write_atomic_from_reader(&atomic_streamed, &mut atomic_reader)
            .await?,
        13
    );
    assert_eq!(client.read(&atomic_streamed).await?, b"atomic-reader");
    assert!(client.remove_if_exists(&atomic_streamed).await?);
    assert!(client.remove_if_exists(&atomic).await?);
    let mut reader = &b"streamed"[..];
    assert_eq!(client.write_from_reader(&streamed, &mut reader).await?, 8);
    assert_eq!(client.read(&streamed).await?, b"streamed");
    client.remove(&streamed).await?;
    client.write(&appended, b"a").await?;
    assert_eq!(client.append(&appended, b"bc").await?, 2);
    let mut append_reader = &b"de"[..];
    assert_eq!(
        client
            .append_from_reader(&appended, &mut append_reader)
            .await?,
        2
    );
    assert_eq!(client.read(&appended).await?, b"abcde");
    client.remove(&appended).await?;
    assert_eq!(client.read(&file).await?, b"nfs-rs-live");
    client.set_mode(&file, 0o600).await?;
    assert_eq!(client.metadata(&file).await?.mode & 0o777, 0o600);
    assert_eq!(client.read_at(&file, 4, 2).await?, b"rs");
    assert_eq!(client.read_exact_at(&file, 4, 2).await?, b"rs");
    assert_eq!(client.read_range(&file, 4, 7).await?, b"rs-live");
    let mut range = Vec::new();
    assert_eq!(
        client.read_range_to_writer(&file, 4, 7, &mut range).await?,
        7
    );
    assert_eq!(range, b"rs-live");
    client.write_at(&file, 4, b"RS").await?;
    assert_eq!(client.read(&file).await?, b"nfs-RS-live");
    client.truncate(&file, 6).await?;
    assert_eq!(client.read(&file).await?, b"nfs-RS");
    client.commit(&file, 0, 0).await?;
    client.rename(&file, &renamed).await?;
    assert_eq!(client.read(&renamed).await?, b"nfs-RS");
    let copied = join_path(root, "copied.txt");
    let atomic_copied = join_path(root, "atomic-copied.txt");
    assert_eq!(client.copy(&renamed, &copied).await?, 6);
    assert_eq!(client.read(&copied).await?, b"nfs-RS");
    assert_eq!(client.copy_atomic(&renamed, &atomic_copied).await?, 6);
    assert_eq!(client.read(&atomic_copied).await?, b"nfs-RS");
    assert!(client.remove_if_exists(&atomic_copied).await?);
    assert!(client.remove_if_exists(&copied).await?);
    assert!(client.remove_if_exists(&renamed).await?);
    exercise_v3_tokio_large_io(client, root).await?;
    exercise_v3_tokio_paged_dir(client, root).await?;
    client.reconnect().await?;
    assert!(client.is_dir(root).await?);
    Ok(())
}

#[cfg(feature = "tokio")]
async fn exercise_v4_tokio(client: &mut nfs::v4::tokio::Client, root: &str) -> Result<()> {
    let file = join_path(root, "payload.txt");
    let renamed = join_path(root, "renamed.txt");
    let created = join_path(root, "created.txt");
    let atomic = join_path(root, "atomic.txt");
    let atomic_streamed = join_path(root, "atomic-streamed.txt");
    let streamed = join_path(root, "streamed.txt");
    let appended = join_path(root, "appended.txt");
    let nested_root = join_path(root, "nested");
    let nested_dir = join_path(&nested_root, "a/b");
    let nested_file = join_path(&nested_dir, "leaf.txt");
    let empty_dir = join_path(root, "empty");

    client.renew().await?;
    client.mkdir(root, 0o755).await?;
    assert!(client.is_dir(root).await?);
    assert!(client.root_fsinfo().is_some());
    client.fsinfo(root).await?;
    client.fsstat(root).await?;
    client.pathconf(root).await?;
    client.create_new_with_mode(&created, 0o644).await?;
    assert!(client.is_file(&created).await?);
    assert!(client.create_new(&created).await.is_err());
    assert!(client.remove_if_exists(&created).await?);
    assert!(!client.remove_if_exists(&created).await?);
    client.mkdir(&empty_dir, 0o755).await?;
    assert!(client.rmdir_if_exists(&empty_dir).await?);
    assert!(!client.rmdir_if_exists(&empty_dir).await?);
    client.create_dir_all(&nested_dir, 0o755).await?;
    client.write(&nested_file, b"nested").await?;
    assert!(client.is_file(&nested_file).await?);
    assert_eq!(client.read(&nested_file).await?, b"nested");
    assert!(
        client
            .read_dir_limited(&nested_dir, 16)
            .await?
            .iter()
            .any(|entry| entry.name == "leaf.txt")
    );
    let page = client.read_dir_page_limited(&nested_dir, None, 16).await?;
    assert!(page.entries.iter().any(|entry| entry.name == "leaf.txt"));
    assert!(client.remove_all_if_exists(&nested_root).await?);
    assert!(!client.remove_all_if_exists(&nested_root).await?);
    assert!(!client.exists(&nested_root).await?);
    client.write(&file, b"nfs-rs-live").await?;
    client.write_atomic(&atomic, b"atomic").await?;
    assert_eq!(client.read(&atomic).await?, b"atomic");
    client
        .write_atomic_with_mode(&atomic, b"atomic-replaced", 0o644)
        .await?;
    assert_eq!(client.read(&atomic).await?, b"atomic-replaced");
    let mut atomic_reader = &b"atomic-reader"[..];
    assert_eq!(
        client
            .write_atomic_from_reader(&atomic_streamed, &mut atomic_reader)
            .await?,
        13
    );
    assert_eq!(client.read(&atomic_streamed).await?, b"atomic-reader");
    assert!(client.remove_if_exists(&atomic_streamed).await?);
    assert!(client.remove_if_exists(&atomic).await?);
    let mut reader = &b"streamed"[..];
    assert_eq!(client.write_from_reader(&streamed, &mut reader).await?, 8);
    assert_eq!(client.read(&streamed).await?, b"streamed");
    client.remove(&streamed).await?;
    client.write(&appended, b"a").await?;
    assert_eq!(client.append(&appended, b"bc").await?, 2);
    let mut append_reader = &b"de"[..];
    assert_eq!(
        client
            .append_from_reader(&appended, &mut append_reader)
            .await?,
        2
    );
    assert_eq!(client.read(&appended).await?, b"abcde");
    client.remove(&appended).await?;
    assert_eq!(client.read(&file).await?, b"nfs-rs-live");
    client.set_mode(&file, 0o600).await?;
    if let Some(mode) = client.metadata(&file).await?.mode {
        assert_eq!(mode & 0o777, 0o600);
    }
    client.setattr(&file, &nfs::v4::SetAttrs::size(4)).await?;
    assert_eq!(client.read(&file).await?, b"nfs-");
    client.write(&file, b"nfs-rs-live").await?;
    assert_eq!(client.read_at(&file, 4, 2).await?, b"rs");
    assert_eq!(client.read_exact_at(&file, 4, 2).await?, b"rs");
    assert_eq!(client.read_range(&file, 4, 7).await?, b"rs-live");
    let mut range = Vec::new();
    assert_eq!(
        client.read_range_to_writer(&file, 4, 7, &mut range).await?,
        7
    );
    assert_eq!(range, b"rs-live");
    client.write_at(&file, 4, b"RS").await?;
    assert_eq!(client.read(&file).await?, b"nfs-RS-live");
    client.truncate(&file, 6).await?;
    assert_eq!(client.read(&file).await?, b"nfs-RS");
    client.commit(&file, 0, 0).await?;
    client.rename(&file, &renamed).await?;
    assert_eq!(client.read(&renamed).await?, b"nfs-RS");
    let copied = join_path(root, "copied.txt");
    let atomic_copied = join_path(root, "atomic-copied.txt");
    assert_eq!(client.copy(&renamed, &copied).await?, 6);
    assert_eq!(client.read(&copied).await?, b"nfs-RS");
    assert_eq!(client.copy_atomic(&renamed, &atomic_copied).await?, 6);
    assert_eq!(client.read(&atomic_copied).await?, b"nfs-RS");
    assert!(client.remove_if_exists(&atomic_copied).await?);
    assert!(client.remove_if_exists(&copied).await?);
    assert!(client.remove_if_exists(&renamed).await?);
    exercise_v4_tokio_large_io(client, root).await?;
    exercise_v4_tokio_paged_dir(client, root).await?;
    client.reconnect().await?;
    assert!(client.is_dir(root).await?);
    Ok(())
}

#[cfg(feature = "blocking")]
fn exercise_v3_blocking_large_io(client: &mut nfs::v3::blocking::Client, root: &str) -> Result<()> {
    let path = join_path(root, "large.bin");
    let mut expected = patterned_bytes(LARGE_PAYLOAD_SIZE);
    let range_end = LARGE_RANGE_OFFSET + LARGE_RANGE_LEN;

    let mut reader = Cursor::new(expected.as_slice());
    assert_eq!(
        client.write_from_reader(&path, &mut reader)?,
        expected.len() as u64
    );
    let mut sink = Vec::new();
    assert_eq!(
        client.read_to_writer(&path, &mut sink)?,
        expected.len() as u64
    );
    assert_eq!(sink, expected);
    assert_eq!(
        client.read_range(&path, LARGE_RANGE_OFFSET as u64, LARGE_RANGE_LEN as u64)?,
        expected[LARGE_RANGE_OFFSET..range_end].to_vec()
    );
    let mut range = Vec::new();
    assert_eq!(
        client.read_range_to_writer(
            &path,
            LARGE_RANGE_OFFSET as u64,
            LARGE_RANGE_LEN as u64,
            &mut range
        )?,
        LARGE_RANGE_LEN as u64
    );
    assert_eq!(range, expected[LARGE_RANGE_OFFSET..range_end].to_vec());
    assert_eq!(
        client.read_exact_at(&path, LARGE_RANGE_OFFSET as u64, 32)?,
        expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 32].to_vec()
    );
    client.write_at(&path, LARGE_RANGE_OFFSET as u64, b"RANGE")?;
    expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 5].copy_from_slice(b"RANGE");
    assert_eq!(
        client.read_at(&path, LARGE_RANGE_OFFSET as u64, 5)?,
        b"RANGE"
    );
    assert_eq!(client.read(&path)?, expected);
    assert!(client.remove_if_exists(&path)?);
    Ok(())
}

#[cfg(feature = "blocking")]
fn exercise_v4_blocking_large_io(client: &mut nfs::v4::blocking::Client, root: &str) -> Result<()> {
    let path = join_path(root, "large.bin");
    let mut expected = patterned_bytes(LARGE_PAYLOAD_SIZE);
    let range_end = LARGE_RANGE_OFFSET + LARGE_RANGE_LEN;

    let mut reader = Cursor::new(expected.as_slice());
    assert_eq!(
        client.write_from_reader(&path, &mut reader)?,
        expected.len() as u64
    );
    let mut sink = Vec::new();
    assert_eq!(
        client.read_to_writer(&path, &mut sink)?,
        expected.len() as u64
    );
    assert_eq!(sink, expected);
    assert_eq!(
        client.read_range(&path, LARGE_RANGE_OFFSET as u64, LARGE_RANGE_LEN as u64)?,
        expected[LARGE_RANGE_OFFSET..range_end].to_vec()
    );
    let mut range = Vec::new();
    assert_eq!(
        client.read_range_to_writer(
            &path,
            LARGE_RANGE_OFFSET as u64,
            LARGE_RANGE_LEN as u64,
            &mut range
        )?,
        LARGE_RANGE_LEN as u64
    );
    assert_eq!(range, expected[LARGE_RANGE_OFFSET..range_end].to_vec());
    assert_eq!(
        client.read_exact_at(&path, LARGE_RANGE_OFFSET as u64, 32)?,
        expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 32].to_vec()
    );
    client.write_at(&path, LARGE_RANGE_OFFSET as u64, b"RANGE")?;
    expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 5].copy_from_slice(b"RANGE");
    assert_eq!(
        client.read_at(&path, LARGE_RANGE_OFFSET as u64, 5)?,
        b"RANGE"
    );
    assert_eq!(client.read(&path)?, expected);
    assert!(client.remove_if_exists(&path)?);
    Ok(())
}

#[cfg(feature = "tokio")]
async fn exercise_v3_tokio_large_io(client: &mut nfs::v3::tokio::Client, root: &str) -> Result<()> {
    let path = join_path(root, "large.bin");
    let mut expected = patterned_bytes(LARGE_PAYLOAD_SIZE);
    let range_end = LARGE_RANGE_OFFSET + LARGE_RANGE_LEN;

    let mut reader = expected.as_slice();
    assert_eq!(
        client.write_from_reader(&path, &mut reader).await?,
        expected.len() as u64
    );
    let mut sink = tokio::io::sink();
    assert_eq!(
        client.read_to_writer(&path, &mut sink).await?,
        expected.len() as u64
    );
    assert_eq!(client.read(&path).await?, expected);
    assert_eq!(
        client
            .read_range(&path, LARGE_RANGE_OFFSET as u64, LARGE_RANGE_LEN as u64)
            .await?,
        expected[LARGE_RANGE_OFFSET..range_end].to_vec()
    );
    let mut range_sink = tokio::io::sink();
    assert_eq!(
        client
            .read_range_to_writer(
                &path,
                LARGE_RANGE_OFFSET as u64,
                LARGE_RANGE_LEN as u64,
                &mut range_sink
            )
            .await?,
        LARGE_RANGE_LEN as u64
    );
    assert_eq!(
        client
            .read_exact_at(&path, LARGE_RANGE_OFFSET as u64, 32)
            .await?,
        expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 32].to_vec()
    );
    client
        .write_at(&path, LARGE_RANGE_OFFSET as u64, b"RANGE")
        .await?;
    expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 5].copy_from_slice(b"RANGE");
    assert_eq!(
        client.read_at(&path, LARGE_RANGE_OFFSET as u64, 5).await?,
        b"RANGE"
    );
    assert_eq!(client.read(&path).await?, expected);
    assert!(client.remove_if_exists(&path).await?);
    Ok(())
}

#[cfg(feature = "tokio")]
async fn exercise_v4_tokio_large_io(client: &mut nfs::v4::tokio::Client, root: &str) -> Result<()> {
    let path = join_path(root, "large.bin");
    let mut expected = patterned_bytes(LARGE_PAYLOAD_SIZE);
    let range_end = LARGE_RANGE_OFFSET + LARGE_RANGE_LEN;

    let mut reader = expected.as_slice();
    assert_eq!(
        client.write_from_reader(&path, &mut reader).await?,
        expected.len() as u64
    );
    let mut sink = tokio::io::sink();
    assert_eq!(
        client.read_to_writer(&path, &mut sink).await?,
        expected.len() as u64
    );
    assert_eq!(client.read(&path).await?, expected);
    assert_eq!(
        client
            .read_range(&path, LARGE_RANGE_OFFSET as u64, LARGE_RANGE_LEN as u64)
            .await?,
        expected[LARGE_RANGE_OFFSET..range_end].to_vec()
    );
    let mut range_sink = tokio::io::sink();
    assert_eq!(
        client
            .read_range_to_writer(
                &path,
                LARGE_RANGE_OFFSET as u64,
                LARGE_RANGE_LEN as u64,
                &mut range_sink
            )
            .await?,
        LARGE_RANGE_LEN as u64
    );
    assert_eq!(
        client
            .read_exact_at(&path, LARGE_RANGE_OFFSET as u64, 32)
            .await?,
        expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 32].to_vec()
    );
    client
        .write_at(&path, LARGE_RANGE_OFFSET as u64, b"RANGE")
        .await?;
    expected[LARGE_RANGE_OFFSET..LARGE_RANGE_OFFSET + 5].copy_from_slice(b"RANGE");
    assert_eq!(
        client.read_at(&path, LARGE_RANGE_OFFSET as u64, 5).await?,
        b"RANGE"
    );
    assert_eq!(client.read(&path).await?, expected);
    assert!(client.remove_if_exists(&path).await?);
    Ok(())
}

#[cfg(feature = "blocking")]
fn exercise_v3_blocking_paged_dir(
    client: &mut nfs::v3::blocking::Client,
    root: &str,
) -> Result<()> {
    let dir = join_path(root, "paged");
    let expected = populate_v3_blocking_dir(client, &dir)?;
    let all = client.read_dir_limited(&dir, PAGED_DIR_LIMIT)?;
    assert_dir_contains_all(all.into_iter().map(|entry| entry.name), &expected);

    let mut seen = BTreeSet::new();
    let mut cursor = None;
    loop {
        let page = client.read_dir_page_limited(&dir, cursor, PAGED_DIR_LIMIT)?;
        for entry in &page.entries {
            if expected.contains(&entry.name) {
                seen.insert(entry.name.clone());
            }
        }
        if page.is_eof() {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(seen, expected);
    assert!(client.remove_all_if_exists(&dir)?);
    Ok(())
}

#[cfg(feature = "blocking")]
fn exercise_v4_blocking_paged_dir(
    client: &mut nfs::v4::blocking::Client,
    root: &str,
) -> Result<()> {
    let dir = join_path(root, "paged");
    let expected = populate_v4_blocking_dir(client, &dir)?;
    let all = client.read_dir_limited(&dir, PAGED_DIR_LIMIT)?;
    assert_dir_contains_all(all.into_iter().map(|entry| entry.name), &expected);

    let mut seen = BTreeSet::new();
    let mut cursor = None;
    loop {
        let page = client.read_dir_page_limited(&dir, cursor, PAGED_DIR_LIMIT)?;
        for entry in &page.entries {
            if expected.contains(&entry.name) {
                seen.insert(entry.name.clone());
            }
        }
        if page.is_eof() {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(seen, expected);
    assert!(client.remove_all_if_exists(&dir)?);
    Ok(())
}

#[cfg(feature = "tokio")]
async fn exercise_v3_tokio_paged_dir(
    client: &mut nfs::v3::tokio::Client,
    root: &str,
) -> Result<()> {
    let dir = join_path(root, "paged");
    let expected = populate_v3_tokio_dir(client, &dir).await?;
    let all = client.read_dir_limited(&dir, PAGED_DIR_LIMIT).await?;
    assert_dir_contains_all(all.into_iter().map(|entry| entry.name), &expected);

    let mut seen = BTreeSet::new();
    let mut cursor = None;
    loop {
        let page = client
            .read_dir_page_limited(&dir, cursor, PAGED_DIR_LIMIT)
            .await?;
        for entry in &page.entries {
            if expected.contains(&entry.name) {
                seen.insert(entry.name.clone());
            }
        }
        if page.is_eof() {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(seen, expected);
    assert!(client.remove_all_if_exists(&dir).await?);
    Ok(())
}

#[cfg(feature = "tokio")]
async fn exercise_v4_tokio_paged_dir(
    client: &mut nfs::v4::tokio::Client,
    root: &str,
) -> Result<()> {
    let dir = join_path(root, "paged");
    let expected = populate_v4_tokio_dir(client, &dir).await?;
    let all = client.read_dir_limited(&dir, PAGED_DIR_LIMIT).await?;
    assert_dir_contains_all(all.into_iter().map(|entry| entry.name), &expected);

    let mut seen = BTreeSet::new();
    let mut cursor = None;
    loop {
        let page = client
            .read_dir_page_limited(&dir, cursor, PAGED_DIR_LIMIT)
            .await?;
        for entry in &page.entries {
            if expected.contains(&entry.name) {
                seen.insert(entry.name.clone());
            }
        }
        if page.is_eof() {
            break;
        }
        cursor = page.next_cursor;
    }
    assert_eq!(seen, expected);
    assert!(client.remove_all_if_exists(&dir).await?);
    Ok(())
}

#[cfg(feature = "blocking")]
fn populate_v3_blocking_dir(
    client: &mut nfs::v3::blocking::Client,
    dir: &str,
) -> Result<BTreeSet<String>> {
    client.mkdir(dir, 0o755)?;
    let mut expected = BTreeSet::new();
    for name in paged_entry_names() {
        client.write(&join_path(dir, &name), name.as_bytes())?;
        expected.insert(name);
    }
    Ok(expected)
}

#[cfg(feature = "blocking")]
fn populate_v4_blocking_dir(
    client: &mut nfs::v4::blocking::Client,
    dir: &str,
) -> Result<BTreeSet<String>> {
    client.mkdir(dir, 0o755)?;
    let mut expected = BTreeSet::new();
    for name in paged_entry_names() {
        client.write(&join_path(dir, &name), name.as_bytes())?;
        expected.insert(name);
    }
    Ok(expected)
}

#[cfg(feature = "tokio")]
async fn populate_v3_tokio_dir(
    client: &mut nfs::v3::tokio::Client,
    dir: &str,
) -> Result<BTreeSet<String>> {
    client.mkdir(dir, 0o755).await?;
    let mut expected = BTreeSet::new();
    for name in paged_entry_names() {
        client
            .write(&join_path(dir, &name), name.as_bytes())
            .await?;
        expected.insert(name);
    }
    Ok(expected)
}

#[cfg(feature = "tokio")]
async fn populate_v4_tokio_dir(
    client: &mut nfs::v4::tokio::Client,
    dir: &str,
) -> Result<BTreeSet<String>> {
    client.mkdir(dir, 0o755).await?;
    let mut expected = BTreeSet::new();
    for name in paged_entry_names() {
        client
            .write(&join_path(dir, &name), name.as_bytes())
            .await?;
        expected.insert(name);
    }
    Ok(expected)
}

fn finish(flow: Result<()>, cleanup: Result<()>, teardown: Result<()>) -> Result<()> {
    flow?;
    cleanup?;
    teardown
}

fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 31 + index / 7) % 251) as u8)
        .collect()
}

fn paged_entry_names() -> Vec<String> {
    (0..PAGED_DIR_ENTRIES)
        .map(|index| format!("entry-{index:02}-abcdefghijklmnopqrstuvwxyz0123456789.txt"))
        .collect()
}

fn assert_dir_contains_all(names: impl Iterator<Item = String>, expected: &BTreeSet<String>) {
    let actual = names
        .filter(|name| expected.contains(name))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, *expected);
}

fn env_var(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn unique_path(prefix: &str, protocol: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    join_path(
        prefix,
        &format!("nfs-rs-live-{protocol}-{}-{nanos}", std::process::id()),
    )
}

fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}
