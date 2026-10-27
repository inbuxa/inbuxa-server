/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 *
 * Modified by Coffey Labs in 2026 for INBUXA.
 */

#[cfg(any(target_os = "linux", all(test, inbuxa_tests)))]
const CGROUP_V1_ROOT: &str = "/sys/fs/cgroup/memory";
#[cfg(any(target_os = "linux", all(test, inbuxa_tests)))]
const CGROUP_V1_FILES: &[&str] = &["memory.limit_in_bytes"];
#[cfg(any(target_os = "linux", all(test, inbuxa_tests)))]
const CGROUP_V2_ROOT: &str = "/sys/fs/cgroup";
#[cfg(any(target_os = "linux", all(test, inbuxa_tests)))]
const CGROUP_V2_FILES: &[&str] = &["memory.max", "memory.high"];

pub fn available_memory() -> Option<u64> {
    physical_memory()
        .into_iter()
        .chain(cgroup_memory_limit())
        .filter(|memory| *memory > 0)
        .min()
}

#[cfg(unix)]
fn physical_memory() -> Option<u64> {
    let (pages, page_size) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    u64::try_from(pages)
        .ok()?
        .checked_mul(u64::try_from(page_size).ok()?)
}

#[cfg(windows)]
fn physical_memory() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    (unsafe { GlobalMemoryStatusEx(&mut status) } != 0).then_some(status.ullTotalPhys)
}

#[cfg(not(any(unix, windows)))]
fn physical_memory() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn cgroup_memory_limit() -> Option<u64> {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .filter_map(CgroupMemory::parse)
        .flat_map(CgroupMemory::limit_files)
        .filter_map(|file| std::fs::read_to_string(file).ok())
        .filter_map(|limit| parse_cgroup_limit(&limit))
        .min()
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_limit() -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", all(test, inbuxa_tests)))]
#[derive(Clone, Copy)]
struct CgroupMemory<'x> {
    root: &'static str,
    files: &'static [&'static str],
    path: &'x str,
}

#[cfg(any(target_os = "linux", all(test, inbuxa_tests)))]
impl<'x> CgroupMemory<'x> {
    fn parse(line: &'x str) -> Option<Self> {
        let (_, entry) = line.split_once(':')?;
        let (controllers, path) = entry.split_once(':')?;
        let (root, files) = if controllers.is_empty() {
            (CGROUP_V2_ROOT, CGROUP_V2_FILES)
        } else if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            (CGROUP_V1_ROOT, CGROUP_V1_FILES)
        } else {
            return None;
        };
        Some(CgroupMemory {
            root,
            files,
            path: path.trim_end_matches('/'),
        })
    }

    fn limit_files(self) -> impl Iterator<Item = String> + 'x {
        let Self { root, files, path } = self;
        std::iter::successors(Some(path), |path| {
            path.rsplit_once('/').map(|(parent, _)| parent)
        })
        .flat_map(move |dir| files.iter().map(move |file| format!("{root}{dir}/{file}")))
    }
}

#[cfg(any(target_os = "linux", all(test, inbuxa_tests)))]
fn parse_cgroup_limit(contents: &str) -> Option<u64> {
    contents.trim().parse().ok()
}

