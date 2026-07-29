"""Private race-safe file publication helpers for exploratory benchmark tools."""

from __future__ import annotations

import errno
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


class SecurePathError(ValueError):
    """Raised when a path cannot be accessed without following aliases."""


def _absolute(path: Path) -> Path:
    # Resolving would follow precisely the symlinks this helper must reject.
    return Path(os.path.abspath(path.expanduser()))  # noqa: PTH100


def _identity_from_stat(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _existing_identities(paths: Iterable[Path]) -> set[tuple[int, int]]:
    identities: set[tuple[int, int]] = set()
    for path in paths:
        try:
            identities.add(_identity_from_stat(os.stat(path)))  # noqa: PTH116
        except FileNotFoundError:
            continue
        except OSError as error:
            raise SecurePathError(f"cannot inspect protected path {path}: {error}") from error
    return identities


def _open_parent(
    path: Path,
    *,
    create: bool,
    forbidden_roots: tuple[Path, ...] = (),
) -> tuple[int, str, Path] | None:
    absolute = _absolute(path)
    if not absolute.name:
        raise SecurePathError(f"destination must name a file: {path}")
    root_identities = _existing_identities(forbidden_roots)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor, flags)
    try:
        if _identity_from_stat(os.fstat(descriptor)) in root_identities:
            raise SecurePathError(f"path is inside a protected directory: {path}")
        for component in absolute.parent.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    return None
                with suppress(FileExistsError):
                    os.mkdir(component, dir_fd=descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise SecurePathError(
                        f"path contains a symlink or non-directory component: {path}"
                    ) from error
                raise
            os.close(descriptor)
            descriptor = child
            if _identity_from_stat(os.fstat(descriptor)) in root_identities:
                raise SecurePathError(f"path is inside a protected directory: {path}")
        return descriptor, absolute.name, absolute
    except BaseException:
        os.close(descriptor)
        raise


def _forbidden_file_addresses(paths: Iterable[Path]) -> set[tuple[int, int, str]]:
    addresses: set[tuple[int, int, str]] = set()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    for path in paths:
        absolute = _absolute(path)
        try:
            descriptor = os.open(absolute.parent, flags)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise SecurePathError(f"cannot inspect protected path {path}: {error}") from error
        try:
            device, inode = _identity_from_stat(os.fstat(descriptor))
            addresses.add((device, inode, absolute.name))
        finally:
            os.close(descriptor)
    return addresses


def ensure_publishable(
    destination: Path,
    *,
    forbidden_files: tuple[Path, ...] = (),
    forbidden_roots: tuple[Path, ...] = (),
) -> None:
    """Check a destination without following symlinked path components."""
    try:
        opened = _open_parent(destination, create=False, forbidden_roots=forbidden_roots)
    except OSError as error:
        raise SecurePathError(f"cannot inspect destination {destination}: {error}") from error
    if opened is None:
        return
    descriptor, name, _absolute_path = opened
    try:
        device, inode = _identity_from_stat(os.fstat(descriptor))
        if (device, inode, name) in _forbidden_file_addresses(forbidden_files):
            raise SecurePathError(f"refusing to target protected file: {destination}")
        try:
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise SecurePathError(f"destination already exists: {destination}")
    except OSError as error:
        raise SecurePathError(f"cannot inspect destination {destination}: {error}") from error
    finally:
        os.close(descriptor)


def publish_exclusive_bytes(  # noqa: PLR0912, PLR0915
    destination: Path,
    content: bytes,
    *,
    forbidden_files: tuple[Path, ...] = (),
    forbidden_roots: tuple[Path, ...] = (),
) -> None:
    """Publish bytes exclusively through one stable destination-directory FD."""
    try:
        opened = _open_parent(destination, create=True, forbidden_roots=forbidden_roots)
        assert opened is not None
        directory_fd, name, _absolute_path = opened
        temporary_name: str | None = None
        file_fd: int | None = None
        try:
            device, inode = _identity_from_stat(os.fstat(directory_fd))
            if (device, inode, name) in _forbidden_file_addresses(forbidden_files):
                raise SecurePathError(f"refusing to target protected file: {destination}")
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise SecurePathError(f"destination already exists: {destination}")

            for _attempt in range(100):
                candidate = f".{name}.{secrets.token_hex(12)}.tmp"
                try:
                    file_fd = os.open(
                        candidate,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=directory_fd,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            if file_fd is None or temporary_name is None:
                raise SecurePathError(f"cannot allocate temporary file for {destination}")

            view = memoryview(content)
            while view:
                written = os.write(file_fd, view)
                if written == 0:
                    raise OSError("short write while publishing")
                view = view[written:]
            os.fsync(file_fd)
            os.close(file_fd)
            file_fd = None
            try:
                os.link(
                    temporary_name,
                    name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise SecurePathError(f"destination already exists: {destination}") from error
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_name = None
            os.fsync(directory_fd)
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if temporary_name is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=directory_fd)
            os.close(directory_fd)
    except SecurePathError:
        raise
    except OSError as error:
        raise SecurePathError(f"cannot publish {destination}: {error}") from error


def read_secure_regular_file(
    path: Path,
    *,
    forbidden_files: tuple[Path, ...] = (),
) -> bytes | None:
    """Read a regular single-link file without following any symlink component."""
    try:
        opened = _open_parent(path, create=False)
        if opened is None:
            return None
        directory_fd, name, _absolute_path = opened
        file_fd: int | None = None
        try:
            try:
                file_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return None
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode):
                raise SecurePathError(f"cache is not a regular file: {path}")
            if info.st_nlink != 1:
                raise SecurePathError(f"cache must have exactly one hard link: {path}")
            if _identity_from_stat(info) in _existing_identities(forbidden_files):
                raise SecurePathError(f"cache aliases a protected or input file: {path}")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(file_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(directory_fd)
    except SecurePathError:
        raise
    except OSError as error:
        raise SecurePathError(f"cannot read cache {path}: {error}") from error
