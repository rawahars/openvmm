// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only support for flat VMDK descriptor files.

#![forbid(unsafe_code)]

mod descriptor;

pub use descriptor::ParseError;

use descriptor::MAX_EXTENTS;
use disk_backend::DiskError;
use disk_backend::DiskIo;
use disk_backend::UnmapBehavior;
use disk_backend::resolve::ResolveDiskParameters;
use disk_backend::resolve::ResolvedDisk;
use disk_backend_resources::VmdkDiskHandle;
use disk_backend_resources::VmdkExtent;
use guestmem::MemoryWrite;
use inspect::Inspect;
use scsi_buffers::RequestBuffers;
use std::collections::HashMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use vm_resource::ResolveResource;
use vm_resource::declare_static_resolver;
use vm_resource::kind::DiskHandleKind;

const SECTOR_SIZE: u64 = 512;
const PHYSICAL_SECTOR_SIZE: u32 = 4096;
const MAX_DESCRIPTOR_SIZE: u64 = 16 * 1024 * 1024;
const MAX_SECTOR_COUNT: u64 = (i64::MAX as u64) / SECTOR_SIZE;
// Mesh can transport at most 64 handles in one resource message.
const MAX_SOURCE_FILES: usize = 64;

/// An error opening or validating a flat VMDK.
#[derive(Debug, Error)]
pub enum OpenError {
    /// The descriptor file could not be opened.
    #[error("failed to open VMDK descriptor '{}'", path.display())]
    OpenDescriptor {
        /// Descriptor path.
        path: PathBuf,
        /// I/O error.
        #[source]
        source: io::Error,
    },
    /// Descriptor metadata could not be read.
    #[error("failed to read metadata for VMDK descriptor '{}'", path.display())]
    DescriptorMetadata {
        /// Descriptor path.
        path: PathBuf,
        /// I/O error.
        #[source]
        source: io::Error,
    },
    /// The descriptor is not a regular file.
    #[error("VMDK descriptor '{}' is not a regular file", .0.display())]
    DescriptorNotFile(PathBuf),
    /// The descriptor is larger than the accepted limit.
    #[error("VMDK descriptor is larger than {MAX_DESCRIPTOR_SIZE} bytes")]
    DescriptorTooLarge,
    /// The descriptor file could not be read.
    #[error("failed to read VMDK descriptor '{}'", path.display())]
    ReadDescriptor {
        /// Descriptor path.
        path: PathBuf,
        /// I/O error.
        #[source]
        source: io::Error,
    },
    /// The descriptor content is invalid or unsupported.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// A referenced extent file could not be opened.
    #[error("failed to open VMDK extent '{}'", path.display())]
    OpenExtent {
        /// Extent path.
        path: PathBuf,
        /// I/O error.
        #[source]
        source: io::Error,
    },
    /// Extent metadata could not be read.
    #[error("failed to read metadata for VMDK source file {index}")]
    ExtentMetadata {
        /// Source file index.
        index: usize,
        /// I/O error.
        #[source]
        source: io::Error,
    },
    /// A referenced extent is not a regular file.
    #[error("VMDK source file {0} is not a regular file")]
    ExtentNotFile(usize),
    /// The supplied extent map is invalid.
    #[error("invalid VMDK extent map: {0}")]
    InvalidLayout(String),
    /// The descriptor references too many distinct source files.
    #[error("VMDK descriptor references more than {MAX_SOURCE_FILES} distinct source files")]
    TooManySourceFiles,
}

/// Opens and validates a flat VMDK descriptor and all of its extent files.
pub fn open_vmdk(path: &Path) -> Result<VmdkDiskHandle, OpenError> {
    let mut descriptor =
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(|source| OpenError::OpenDescriptor {
                path: path.to_owned(),
                source,
            })?;
    let metadata = descriptor
        .metadata()
        .map_err(|source| OpenError::DescriptorMetadata {
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(OpenError::DescriptorNotFile(path.to_owned()));
    }
    if metadata.len() > MAX_DESCRIPTOR_SIZE {
        return Err(OpenError::DescriptorTooLarge);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    descriptor
        .by_ref()
        .take(MAX_DESCRIPTOR_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| OpenError::ReadDescriptor {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > MAX_DESCRIPTOR_SIZE {
        return Err(OpenError::DescriptorTooLarge);
    }

    let parsed = descriptor::parse_descriptor(&bytes)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file_indices = HashMap::new();
    let mut files = Vec::new();
    let mut extents = Vec::with_capacity(parsed.extents.len());

    for extent in parsed.extents {
        let extent_path = Path::new(&extent.path);
        if extent_path.has_root() && !extent_path.is_absolute() {
            return Err(OpenError::InvalidLayout(format!(
                "extent path '{}' is not absolute on this platform",
                extent_path.display()
            )));
        }
        let extent_path = if extent_path.is_absolute() {
            extent_path.to_owned()
        } else {
            parent.join(extent_path)
        };
        let file_index = if let Some(&file_index) = file_indices.get(&extent_path) {
            file_index
        } else {
            if files.len() == MAX_SOURCE_FILES {
                return Err(OpenError::TooManySourceFiles);
            }
            let file = OpenOptions::new()
                .read(true)
                .open(&extent_path)
                .map_err(|source| OpenError::OpenExtent {
                    path: extent_path.clone(),
                    source,
                })?;
            let file_index = u32::try_from(files.len())
                .map_err(|_| OpenError::InvalidLayout("too many source files".into()))?;
            files.push(file);
            file_indices.insert(extent_path, file_index);
            file_index
        };
        extents.push(VmdkExtent {
            file_index,
            sector_count: extent.sector_count,
            file_offset: extent.file_offset,
        });
    }

    // Validate before transport; the resolver repeats this for untrusted handles.
    build_layout(&files, &extents)?;
    Ok(VmdkDiskHandle { files, extents })
}

#[derive(Debug)]
struct Source {
    file: Arc<File>,
    length: u64,
}

#[derive(Clone, Debug, Inspect)]
struct Extent {
    source_index: usize,
    virtual_start_sector: u64,
    sector_count: u64,
    source_start_sector: u64,
}

#[derive(Debug)]
struct Layout {
    source_lengths: Vec<u64>,
    extents: Vec<Extent>,
    sector_count: u64,
}

#[derive(Debug, Inspect)]
struct VmdkDisk {
    #[inspect(skip)]
    sources: Vec<Source>,
    #[inspect(iter_by_index)]
    extents: Vec<Extent>,
    sector_count: u64,
}

impl VmdkDisk {
    fn new(handle: VmdkDiskHandle) -> Result<Self, OpenError> {
        let layout = build_layout(&handle.files, &handle.extents)?;
        let sources = handle
            .files
            .into_iter()
            .zip(layout.source_lengths)
            .map(|(file, length)| Source {
                file: Arc::new(file),
                length,
            })
            .collect();
        Ok(Self {
            sources,
            extents: layout.extents,
            sector_count: layout.sector_count,
        })
    }

    fn plan_read(&self, sector: u64, length: usize) -> Result<Vec<ReadSegment>, DiskError> {
        if !length.is_multiple_of(SECTOR_SIZE as usize) {
            return Err(DiskError::InvalidInput);
        }
        let sector_count =
            u64::try_from(length / SECTOR_SIZE as usize).map_err(|_| DiskError::InvalidInput)?;
        let end_sector = sector
            .checked_add(sector_count)
            .ok_or(DiskError::IllegalBlock)?;
        if end_sector > self.sector_count {
            return Err(DiskError::IllegalBlock);
        }
        if sector_count == 0 {
            return Ok(Vec::new());
        }

        let mut extent_index = self
            .extents
            .partition_point(|extent| extent.virtual_start_sector <= sector)
            .checked_sub(1)
            .ok_or_else(invalid_extent_map)?;
        let mut current_sector = sector;
        let mut output_offset = 0;
        let mut segments = Vec::new();

        while current_sector < end_sector {
            let extent = self
                .extents
                .get(extent_index)
                .ok_or_else(invalid_extent_map)?;
            let extent_end = extent
                .virtual_start_sector
                .checked_add(extent.sector_count)
                .ok_or_else(invalid_extent_map)?;
            if current_sector < extent.virtual_start_sector || current_sector >= extent_end {
                return Err(invalid_extent_map());
            }

            let segment_sectors = (end_sector - current_sector).min(extent_end - current_sector);
            let segment_length = usize::try_from(
                segment_sectors
                    .checked_mul(SECTOR_SIZE)
                    .ok_or(DiskError::InvalidInput)?,
            )
            .map_err(|_| DiskError::InvalidInput)?;
            let source_sector = extent
                .source_start_sector
                .checked_add(current_sector - extent.virtual_start_sector)
                .ok_or_else(invalid_extent_map)?;
            let source_offset = source_sector
                .checked_mul(SECTOR_SIZE)
                .ok_or_else(invalid_extent_map)?;
            let source = self
                .sources
                .get(extent.source_index)
                .ok_or_else(invalid_extent_map)?;

            segments.push(ReadSegment {
                file: source.file.clone(),
                file_length: source.length,
                file_offset: source_offset,
                output_offset,
                length: segment_length,
            });
            output_offset = output_offset
                .checked_add(segment_length)
                .ok_or(DiskError::InvalidInput)?;
            current_sector += segment_sectors;
            extent_index += 1;
        }

        if output_offset != length {
            return Err(invalid_extent_map());
        }
        Ok(segments)
    }
}

fn build_layout(files: &[File], extents: &[VmdkExtent]) -> Result<Layout, OpenError> {
    if extents.is_empty() {
        return Err(OpenError::InvalidLayout("the extent map is empty".into()));
    }
    if extents.len() > MAX_EXTENTS {
        return Err(OpenError::InvalidLayout(format!(
            "the extent map has more than {MAX_EXTENTS} entries"
        )));
    }
    if files.len() > MAX_SOURCE_FILES {
        return Err(OpenError::TooManySourceFiles);
    }

    let mut source_lengths = Vec::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        let metadata = file
            .metadata()
            .map_err(|source| OpenError::ExtentMetadata { index, source })?;
        if !metadata.is_file() {
            return Err(OpenError::ExtentNotFile(index));
        }
        source_lengths.push(metadata.len());
    }

    let mut sector_count = 0u64;
    let mut layout_extents = Vec::with_capacity(extents.len());
    for (index, extent) in extents.iter().enumerate() {
        let source_index = usize::try_from(extent.file_index).map_err(|_| {
            OpenError::InvalidLayout(format!("extent {index} has an invalid source"))
        })?;
        let Some(&source_length) = source_lengths.get(source_index) else {
            return Err(OpenError::InvalidLayout(format!(
                "extent {index} references missing source file {source_index}"
            )));
        };
        if extent.sector_count == 0 {
            return Err(OpenError::InvalidLayout(format!(
                "extent {index} has zero sectors"
            )));
        }
        let source_end = extent
            .file_offset
            .checked_add(extent.sector_count)
            .ok_or_else(|| {
                OpenError::InvalidLayout(format!("extent {index} source range overflows"))
            })?;
        let source_sectors =
            source_length / SECTOR_SIZE + u64::from(source_length % SECTOR_SIZE != 0);
        if source_end > source_sectors {
            return Err(OpenError::InvalidLayout(format!(
                "extent {index} ends at source sector {source_end}, but source file {source_index} has only {source_sectors} sectors"
            )));
        }
        let next_sector_count = sector_count
            .checked_add(extent.sector_count)
            .filter(|count| *count <= MAX_SECTOR_COUNT)
            .ok_or_else(|| OpenError::InvalidLayout("virtual disk size is too large".into()))?;
        layout_extents.push(Extent {
            source_index,
            virtual_start_sector: sector_count,
            sector_count: extent.sector_count,
            source_start_sector: extent.file_offset,
        });
        sector_count = next_sector_count;
    }

    Ok(Layout {
        source_lengths,
        extents: layout_extents,
        sector_count,
    })
}

#[derive(Debug)]
struct ReadSegment {
    file: Arc<File>,
    file_length: u64,
    file_offset: u64,
    output_offset: usize,
    length: usize,
}

fn read_segments(length: usize, segments: Vec<ReadSegment>) -> io::Result<Vec<u8>> {
    let mut data = vec![0; length];
    for segment in segments {
        let output_end = segment
            .output_offset
            .checked_add(segment.length)
            .ok_or_else(|| io::Error::other("invalid VMDK read plan"))?;
        let output = data
            .get_mut(segment.output_offset..output_end)
            .ok_or_else(|| io::Error::other("invalid VMDK read plan"))?;
        let readable_length = usize::try_from(
            segment
                .file_length
                .saturating_sub(segment.file_offset)
                .min(segment.length as u64),
        )
        .map_err(|_| io::Error::other("invalid VMDK read plan"))?;
        let mut completed = 0;
        while completed < readable_length {
            let offset = segment
                .file_offset
                .checked_add(completed as u64)
                .ok_or_else(|| io::Error::other("VMDK source offset overflow"))?;
            let buffer = output
                .get_mut(completed..readable_length)
                .ok_or_else(|| io::Error::other("invalid VMDK read plan"))?;
            match read_at(&segment.file, buffer, offset) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "VMDK extent file was truncated",
                    ));
                }
                Ok(count) => completed += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(data)
}

#[cfg(unix)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

fn invalid_extent_map() -> DiskError {
    DiskError::Io(io::Error::other("invalid VMDK extent map"))
}

impl DiskIo for VmdkDisk {
    fn disk_type(&self) -> &str {
        "vmdk_flat"
    }

    fn sector_count(&self) -> u64 {
        self.sector_count
    }

    fn sector_size(&self) -> u32 {
        SECTOR_SIZE as u32
    }

    fn physical_sector_size(&self) -> u32 {
        PHYSICAL_SECTOR_SIZE
    }

    fn is_fua_respected(&self) -> bool {
        false
    }

    fn is_read_only(&self) -> bool {
        true
    }

    fn disk_id(&self) -> Option<[u8; 16]> {
        None
    }

    async fn read_vectored(
        &self,
        buffers: &RequestBuffers<'_>,
        sector: u64,
    ) -> Result<(), DiskError> {
        let length = buffers.len();
        let segments = self.plan_read(sector, length)?;
        let data = blocking::unblock(move || read_segments(length, segments))
            .await
            .map_err(DiskError::Io)?;
        buffers.writer().write(&data)?;
        Ok(())
    }

    async fn write_vectored(
        &self,
        _buffers: &RequestBuffers<'_>,
        _sector: u64,
        _fua: bool,
    ) -> Result<(), DiskError> {
        Err(DiskError::ReadOnly)
    }

    async fn sync_cache(&self) -> Result<(), DiskError> {
        Ok(())
    }

    fn unmap_behavior(&self) -> UnmapBehavior {
        UnmapBehavior::Ignored
    }

    async fn unmap(
        &self,
        _sector: u64,
        _count: u64,
        _block_level_only: bool,
    ) -> Result<(), DiskError> {
        Ok(())
    }
}

/// Resolves [`VmdkDiskHandle`] resources.
pub struct VmdkResolver;
declare_static_resolver!(VmdkResolver, (DiskHandleKind, VmdkDiskHandle));

/// An error resolving a VMDK disk resource.
#[derive(Debug, Error)]
pub enum ResolveVmdkError {
    /// The resource requested a writable disk.
    #[error("VMDK disks are read-only")]
    ReadWriteUnsupported,
    /// The VMDK resource is invalid.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// The resolved disk metadata is invalid.
    #[error("invalid disk")]
    InvalidDisk(#[source] disk_backend::InvalidDisk),
}

impl ResolveResource<DiskHandleKind, VmdkDiskHandle> for VmdkResolver {
    type Output = ResolvedDisk;
    type Error = ResolveVmdkError;

    fn resolve(
        &self,
        resource: VmdkDiskHandle,
        input: ResolveDiskParameters<'_>,
    ) -> Result<Self::Output, Self::Error> {
        resolve_vmdk(resource, input.read_only)
    }
}

fn resolve_vmdk(
    resource: VmdkDiskHandle,
    read_only: bool,
) -> Result<ResolvedDisk, ResolveVmdkError> {
    if !read_only {
        return Err(ResolveVmdkError::ReadWriteUnsupported);
    }
    ResolvedDisk::new(VmdkDisk::new(resource)?).map_err(ResolveVmdkError::InvalidDisk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_backend::Disk;
    use guestmem::GuestMemory;
    use pal_async::async_test;
    use scsi_buffers::OwnedRequestBuffers;

    fn descriptor(create_type: &str, extents: &str) -> String {
        format!(
            "# Disk DescriptorFile\n\
             version=1\n\
             CID=fffffffe\n\
             parentCID=ffffffff\n\
             createType=\"{create_type}\"\n\
             \n\
             # Extent description\n\
             {extents}\n\
             \n\
             # The Disk Data Base\n\
             #DDB\n\
             ddb.adapterType = \"ide\"\n"
        )
    }

    fn write_descriptor(directory: &tempfile::TempDir, contents: &str) -> PathBuf {
        let path = directory.path().join("disk.vmdk");
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn open_disk(path: &Path) -> Disk {
        let handle = open_vmdk(path).unwrap();
        Disk::new(VmdkDisk::new(handle).unwrap()).unwrap()
    }

    async fn read_sectors(disk: &Disk, sector: u64, count: usize) -> Vec<u8> {
        let length = count * SECTOR_SIZE as usize;
        let memory = GuestMemory::allocate(length);
        disk.read_vectored(
            &OwnedRequestBuffers::linear(0, length, true).buffer(&memory),
            sector,
        )
        .await
        .unwrap();
        let mut data = vec![0; length];
        memory.read_at(0, &mut data).unwrap();
        data
    }

    #[test]
    fn parses_kata_32_layer_shape() {
        let mut extents =
            String::from("RW 2048 FLAT \"/run/kata-containers/sandbox/gpt_meta_head.img\" 0\n");
        for layer in (2..=32).rev() {
            extents.push_str(&format!(
                "RW 16 FLAT \"/var/lib/containerd/erofs/snapshots/{layer}/layer.erofs\" 0\n"
            ));
            extents.push_str(&format!(
                "RW 2032 FLAT \"/run/kata-containers/sandbox/pad-{}.img\" 0\n",
                33 - layer
            ));
        }
        extents.push_str("RW 16832 FLAT \"/var/lib/containerd/erofs/snapshots/1/layer.erofs\" 0");

        let parsed =
            descriptor::parse_descriptor(descriptor("twoGbMaxExtentFlat", &extents).as_bytes())
                .unwrap();
        assert_eq!(parsed.extents.len(), 64);
        assert_eq!(
            parsed
                .extents
                .iter()
                .map(|extent| extent.sector_count)
                .sum::<u64>(),
            82368
        );
        assert_eq!(
            parsed.extents.first().unwrap().path,
            "/run/kata-containers/sandbox/gpt_meta_head.img"
        );
        assert_eq!(
            parsed.extents.last().unwrap().path,
            "/var/lib/containerd/erofs/snapshots/1/layer.erofs"
        );
    }

    #[test]
    fn accepts_monolithic_flat_and_crlf() {
        let descriptor =
            descriptor("monolithicFlat", "RW 1 FLAT \"disk data.bin\"").replace('\n', "\r\n");
        let parsed = descriptor::parse_descriptor(descriptor.as_bytes()).unwrap();
        assert_eq!(parsed.extents.len(), 1);
        assert_eq!(parsed.extents[0].file_offset, 0);
        assert_eq!(parsed.extents[0].path, "disk data.bin");

        let descriptor = descriptor
            .replace("parentCID=ffffffff\r\n", "")
            .replace("# The Disk Data Base\r\n#DDB\r\n", "");
        descriptor::parse_descriptor(descriptor.as_bytes()).unwrap();
    }

    #[test]
    fn rejects_unsupported_descriptors() {
        for descriptor in [
            descriptor("monolithicSparse", "RW 1 SPARSE \"disk.bin\" 0"),
            descriptor("twoGbMaxExtentFlat", "NOACCESS 1 FLAT \"disk.bin\" 0"),
            descriptor("twoGbMaxExtentFlat", "RW 1 ZERO \"disk.bin\" 0"),
            descriptor("twoGbMaxExtentFlat", "RW 0 FLAT \"disk.bin\" 0"),
            descriptor("twoGbMaxExtentFlat", "RW 1 FLAT \"../disk.bin\" 0"),
            descriptor("twoGbMaxExtentFlat", "RW 1 FLAT \"disk.bin\" 0 trailing"),
            descriptor(
                "monolithicFlat",
                "RW 1 FLAT \"a.bin\" 0\nRW 1 FLAT \"b.bin\" 0",
            ),
            descriptor("twoGbMaxExtentFlat", "RW 1 FLAT \"disk.bin\" 0")
                .replace("parentCID=ffffffff", "parentCID=12345678"),
            descriptor("twoGbMaxExtentFlat", "RW 1 FLAT \"disk.bin\" 0").replace(
                "parentCID=ffffffff",
                "parentCID=ffffffff\nparentFileNameHint=\"base.vmdk\"",
            ),
        ] {
            assert!(
                descriptor::parse_descriptor(descriptor.as_bytes()).is_err(),
                "descriptor unexpectedly accepted:\n{descriptor}"
            );
        }
    }

    #[async_test]
    async fn reads_across_ordered_extents() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.bin");
        let second = directory.path().join("second file.bin");
        std::fs::write(&first, [[0x10; 512], [0x11; 512]].concat()).unwrap();
        std::fs::write(&second, [[0x20; 512], [0x21; 512], [0x22; 512]].concat()).unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor(
                "twoGbMaxExtentFlat",
                "RW 1 FLAT \"first.bin\" 1\nRDONLY 2 FLAT \"second file.bin\"",
            ),
        );
        let disk = open_disk(&path);

        assert_eq!(disk.sector_count(), 3);
        assert_eq!(
            read_sectors(&disk, 0, 3).await,
            [[0x11; 512], [0x20; 512], [0x21; 512]].concat()
        );
    }

    #[async_test]
    async fn reuses_source_file_at_different_offsets() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join("source.bin"),
            [[0x30; 512], [0x31; 512], [0x32; 512]].concat(),
        )
        .unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor(
                "twoGbMaxExtentFlat",
                "RW 1 FLAT \"source.bin\" 2\nRW 1 FLAT \"source.bin\" 0",
            ),
        );
        let handle = open_vmdk(&path).unwrap();
        assert_eq!(handle.files.len(), 1);
        let disk = Disk::new(VmdkDisk::new(handle).unwrap()).unwrap();

        assert_eq!(
            read_sectors(&disk, 0, 2).await,
            [[0x32; 512], [0x30; 512]].concat()
        );
    }

    #[async_test]
    async fn zero_fills_partial_final_source_sector() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("partial.bin");
        let mut data = vec![0x40; 512];
        data.push(0x41);
        std::fs::write(&source, data).unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor(
                "monolithicFlat",
                &format!("RW 2 FLAT \"{}\" 0", source.display()),
            ),
        );
        let disk = open_disk(&path);

        let data = read_sectors(&disk, 1, 1).await;
        assert_eq!(data[0], 0x41);
        assert!(data[1..].iter().all(|byte| *byte == 0));
    }

    #[async_test]
    async fn reports_post_open_truncation() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.bin");
        std::fs::write(&source, [0x50; 1024]).unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor("monolithicFlat", "RW 2 FLAT \"source.bin\" 0"),
        );
        let disk = open_disk(&path);
        OpenOptions::new()
            .write(true)
            .open(source)
            .unwrap()
            .set_len(512)
            .unwrap();

        let memory = GuestMemory::allocate(512);
        let result = disk
            .read_vectored(
                &OwnedRequestBuffers::linear(0, 512, true).buffer(&memory),
                1,
            )
            .await;
        assert!(matches!(result, Err(DiskError::Io(_))), "{result:?}");
    }

    #[test]
    fn rejects_source_range_past_end() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("source.bin"), [0; 512]).unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor("monolithicFlat", "RW 2 FLAT \"source.bin\" 0"),
        );

        assert!(matches!(open_vmdk(&path), Err(OpenError::InvalidLayout(_))));
    }

    #[test]
    fn rejects_more_than_transportable_source_files() {
        let directory = tempfile::tempdir().unwrap();
        let mut extents = String::new();
        for index in 0..MAX_SOURCE_FILES {
            let name = format!("source-{index}.bin");
            std::fs::write(directory.path().join(&name), [0; 512]).unwrap();
            extents.push_str(&format!("RW 1 FLAT \"{name}\" 0\n"));
        }
        let path = write_descriptor(&directory, &descriptor("twoGbMaxExtentFlat", &extents));
        assert_eq!(open_vmdk(&path).unwrap().files.len(), MAX_SOURCE_FILES);

        let name = format!("source-{MAX_SOURCE_FILES}.bin");
        std::fs::write(directory.path().join(&name), [0; 512]).unwrap();
        extents.push_str(&format!("RW 1 FLAT \"{name}\" 0\n"));
        std::fs::write(&path, descriptor("twoGbMaxExtentFlat", &extents)).unwrap();

        assert!(matches!(
            open_vmdk(&path),
            Err(OpenError::TooManySourceFiles)
        ));
    }

    #[test]
    fn resolver_rejects_writable_disk() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("source.bin"), [0; 512]).unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor("monolithicFlat", "RW 1 FLAT \"source.bin\" 0"),
        );

        assert!(matches!(
            resolve_vmdk(open_vmdk(&path).unwrap(), false),
            Err(ResolveVmdkError::ReadWriteUnsupported)
        ));
    }

    #[async_test]
    async fn read_only_protocol_behavior() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("source.bin"), [0; 1024]).unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor("monolithicFlat", "RW 2 FLAT \"source.bin\" 0"),
        );
        let disk = open_disk(&path);
        let memory = GuestMemory::allocate(512);

        let result = disk
            .write_vectored(
                &OwnedRequestBuffers::linear(0, 512, false).buffer(&memory),
                0,
                false,
            )
            .await;
        assert!(matches!(result, Err(DiskError::ReadOnly)));
        disk.sync_cache().await.unwrap();
        disk.unmap(0, 1, false).await.unwrap();
    }

    #[async_test]
    async fn sector_range_conformance() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("source.bin"), [0; 1024]).unwrap();
        let path = write_descriptor(
            &directory,
            &descriptor("monolithicFlat", "RW 2 FLAT \"source.bin\" 0"),
        );
        storage_tests::sector_range::test_disk_sector_range_conformance(&open_disk(&path)).await;
    }
}
