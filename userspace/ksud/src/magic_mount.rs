use crate::defs::{KSU_MOUNT_SOURCE, MODULE_DIR, SKIP_MOUNT_FILE_NAME, TEMP_DIR};
use crate::magic_mount::NodeFileType::{Directory, RegularFile, Symlink};
use crate::restorecon::{lgetfilecon, lsetfilecon};
use anyhow::{bail, Context, Result};
use rustix::fs::{
    bind_mount, chmod, chown, mount, move_mount, unmount, Gid, MetadataExt, Mode, MountFlags,
    MountPropagationFlags, Uid, UnmountFlags,
};
use rustix::mount::mount_change;
use rustix::path::Arg;
use std::cmp::PartialEq;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::fs::{create_dir, create_dir_all, read_dir, DirEntry, FileType};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum NodeFileType {
    RegularFile,
    Directory,
    Symlink,
}

impl NodeFileType {
    fn from_file_type(file_type: FileType) -> Option<Self> {
        if file_type.is_file() {
            Some(RegularFile)
        } else if file_type.is_dir() {
            Some(Directory)
        } else if file_type.is_symlink() {
            Some(Symlink)
        } else {
            None
        }
    }
}

struct Node {
    name: String,
    file_type: NodeFileType,
    children: HashMap<String, Node>,
    // the module that owned this node
    module_path: Option<PathBuf>,
    replace: bool,
}

impl Node {
    fn collect_module_files<T: AsRef<Path>>(&mut self, module_dir: T) -> Result<bool> {
        let dir = module_dir.as_ref();
        let mut has_file = false;
        for entry in dir.read_dir()?.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".replace" {
                has_file = true;
                self.replace = true;
                continue;
            }

            let file_type = entry.file_type()?;

            let node = match self.children.entry(name.clone()) {
                Entry::Occupied(o) => Some(o.into_mut()),
                Entry::Vacant(v) => {
                    Self::new_module(&name, file_type, dir.join(&name)).map(|it| v.insert(it))
                }
            };

            if let Some(node) = node {
                has_file |= if let Directory = node.file_type {
                    node.collect_module_files(&dir.join(&node.name))?
                } else {
                    true
                }
            }
        }

        Ok(has_file)
    }

    fn new_root<T: ToString>(name: T) -> Self {
        Node {
            name: name.to_string(),
            file_type: Directory,
            children: Default::default(),
            module_path: None,
            replace: false,
        }
    }

    fn new_module<T: ToString, P: AsRef<Path>>(
        name: T,
        file_type: FileType,
        module_path: P,
    ) -> Option<Self> {
        let file_type = NodeFileType::from_file_type(file_type)?;

        Some(Node {
            name: name.to_string(),
            file_type,
            children: Default::default(),
            module_path: Some(PathBuf::from(module_path.as_ref())),
            replace: false,
        })
    }
}

fn collect_module_files() -> Result<Option<Node>> {
    let mut root = Node::new_root("");
    let mut system = Node::new_root("system");
    let module_root = Path::new(MODULE_DIR);
    let mut has_file = false;
    for entry in module_root.read_dir()?.flatten() {
        if !entry.file_type()?.is_dir() {
            continue;
        }

        if entry.path().join("disable").exists() || entry.path().join(SKIP_MOUNT_FILE_NAME).exists() {
            continue;
        }

        let mod_system = entry.path().join("system");
        if !mod_system.is_dir() {
            continue;
        }

        log::debug!("collecting {}", entry.path().display());

        has_file |= system.collect_module_files(&mod_system)?;
    }

    if has_file {
        for partition in vec!["vendor", "system_ext", "product", "odm"] {
            let path_of_root = Path::new("/").join(partition);
            let path_of_system = Path::new("/system").join(partition);
            if path_of_root.is_dir() && path_of_system.is_symlink() {
                let name = partition.to_string();
                if let Some(node) = system.children.remove(&name) {
                    root.children.insert(name, node);
                }
            }
        }
        root.children.insert("system".to_string(), system);
        Ok(Some(root))
    } else {
        Ok(None)
    }
}

fn clone_symlink<Src: AsRef<Path>, Dst: AsRef<Path>>(src: Src, dst: Dst) -> Result<()> {
    symlink(src.as_ref(), dst.as_ref())?;
    lsetfilecon(dst.as_ref(), lgetfilecon(src.as_ref())?.as_str())?;
    Ok(())
}

fn mount_mirror<P: AsRef<Path>, WP: AsRef<Path>>(
    path: P,
    work_dir_path: WP,
    entry: &DirEntry,
) -> Result<()> {
    let path = path.as_ref().join(entry.file_name());
    let work_dir_path = work_dir_path.as_ref().join(entry.file_name());
    let file_type = entry.file_type()?;

    if file_type.is_file() {
        log::debug!(
            "mount mirror file {} -> {}",
            path.display(),
            work_dir_path.display()
        );
        fs::File::create(&work_dir_path)?;
        bind_mount(&path, &work_dir_path)?;
    } else if file_type.is_dir() {
        log::debug!(
            "mount mirror dir {} -> {}",
            path.display(),
            work_dir_path.display()
        );
        create_dir(&work_dir_path)?;
        let metadata = entry.metadata()?;
        chmod(&work_dir_path, Mode::from_raw_mode(metadata.mode()))?;
        unsafe {
            chown(
                &work_dir_path,
                Some(Uid::from_raw(metadata.uid())),
                Some(Gid::from_raw(metadata.gid())),
            )?;
        }
        lsetfilecon(&work_dir_path, lgetfilecon(&path)?.as_str())?;
        for entry in read_dir(&path)?.flatten() {
            mount_mirror(&path, &work_dir_path, &entry)?;
        }
    } else if file_type.is_symlink() {
        log::debug!(
            "create mirror symlink {} -> {}",
            path.display(),
            work_dir_path.display()
        );
        clone_symlink(&path, &work_dir_path)?;
    }

    Ok(())
}

fn do_magic_mount<P: AsRef<Path>, WP: AsRef<Path>>(
    path: P,
    work_dir_path: WP,
    current: Node,
    has_tmpfs: bool,
) -> Result<()> {
    let mut current = current;
    let path = path.as_ref().join(&current.name);
    let work_dir_path = work_dir_path.as_ref().join(&current.name);
    match current.file_type {
        RegularFile => {
            if has_tmpfs {
                fs::File::create(&work_dir_path)?;
            }
            if let Some(module_path) = &current.module_path {
                log::debug!(
                    "mount module file {} -> {}",
                    module_path.display(),
                    work_dir_path.display()
                );
                bind_mount(module_path, &work_dir_path)?;
            } else {
                bail!("cannot mount root file {}!", path.display());
            }
        }
        Symlink => {
            if let Some(module_path) = &current.module_path {
                log::debug!(
                    "create module symlink {} -> {}",
                    module_path.display(),
                    work_dir_path.display()
                );
                clone_symlink(module_path, &work_dir_path)?;
            } else {
                bail!("cannot mount root symlink {}!", path.display());
            }
        }
        Directory => {
            let mut create_tmpfs = false;
            if !has_tmpfs {
                for (name, node) in &current.children {
                    let real_path = path.join(name);
                    let need = if node.file_type == Symlink || !real_path.exists() {
                        true
                    } else {
                        let file_type = real_path.metadata()?.file_type();
                        let file_type =
                            NodeFileType::from_file_type(file_type).unwrap_or(RegularFile);
                        file_type != node.file_type || file_type == Symlink
                    };
                    if need {
                        create_tmpfs = need;
                        break;
                    }
                }
            }

            let has_tmpfs = has_tmpfs || create_tmpfs;

            if has_tmpfs {
                log::debug!(
                    "creating tmpfs skeleton for {} at {}",
                    path.display(),
                    work_dir_path.display()
                );
                create_dir_all(&work_dir_path)?;
                let (metadata, path) = if path.exists() {
                    (path.metadata()?, &path)
                } else if let Some(module_path) = &current.module_path {
                    (module_path.metadata()?, module_path)
                } else {
                    bail!("cannot mount root dir {}!", path.display());
                };
                chmod(&work_dir_path, Mode::from_raw_mode(metadata.mode()))?;
                unsafe {
                    chown(
                        &work_dir_path,
                        Some(Uid::from_raw(metadata.uid())),
                        Some(Gid::from_raw(metadata.gid())),
                    )?;
                }
                lsetfilecon(&work_dir_path, lgetfilecon(&path)?.as_str())?;
            }

            if create_tmpfs {
                log::debug!(
                    "creating tmpfs for {} at {}",
                    path.display(),
                    work_dir_path.display()
                );
                bind_mount(&work_dir_path, &work_dir_path)?;
            }

            if path.exists() && !current.replace {
                for entry in path.read_dir()?.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if let Some(node) = current.children.remove(&name) {
                        do_magic_mount(&path, &work_dir_path, node, has_tmpfs)?;
                    } else if has_tmpfs {
                        mount_mirror(&path, &work_dir_path, &entry)?;
                    }
                }
            }

            if current.replace && current.module_path.is_none() {
                bail!(
                    "dir {} is declared as replaced but it is root!",
                    path.display()
                );
            }

            for node in current.children.into_values() {
                do_magic_mount(&path, &work_dir_path, node, has_tmpfs)?;
            }

            if create_tmpfs {
                log::debug!(
                    "moving tmpfs {} -> {}",
                    work_dir_path.display(),
                    path.display()
                );
                move_mount(&work_dir_path, &path)?;
            }
        }
    }

    Ok(())
}

pub fn magic_mount() -> Result<()> {
    if let Some(root) = collect_module_files()? {
        let tmp_dir = PathBuf::from(TEMP_DIR);
        mount(KSU_MOUNT_SOURCE, &tmp_dir, "tmpfs", MountFlags::empty(), "").context("mount tmp")?;
        mount_change(&tmp_dir, MountPropagationFlags::PRIVATE).context("make tmp private")?;
        let result = do_magic_mount("/", &tmp_dir, root, false);
        if let Err(e) = unmount(&tmp_dir, UnmountFlags::DETACH) {
            log::error!("failed to unmount tmp {}", e);
        }
        result
    } else {
        log::info!("no modules to mount, skipping!");
        Ok(())
    }
}
