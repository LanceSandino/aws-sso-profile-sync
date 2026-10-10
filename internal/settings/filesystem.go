// Settings filesystem reads use descriptor-relative traversal to reject symlink races.
// Regular bounded owner-controlled files are read without modifying any path or metadata.
package settings

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maximumSize = 1 << 20

func canonicalSystemAlias(path string) (string, error) {
	if runtime.GOOS == "darwin" {
		for _, prefix := range []string{"/tmp", "/var"} {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				target, err := os.Readlink(prefix)
				if err == nil {
					if target != "private"+prefix && target != "/private"+prefix {
						return "", invalid("symlink paths are refused")
					}
					return "/private" + path, nil
				}
			}
		}
	}
	return path, nil
}
func read(path string) ([]byte, error) {
	path, err := canonicalSystemAlias(path)
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	descriptor, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalid("file cannot be read securely")
	}
	for _, part := range components[:len(components)-1] {
		next, openErr := unix.Openat(descriptor, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(descriptor)
		if openErr != nil {
			return nil, invalid("file path is unavailable or contains a symlink")
		}
		descriptor = next
	}
	final, err := unix.Openat(descriptor, components[len(components)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	unix.Close(descriptor)
	if err != nil {
		return nil, invalid("file is unavailable or contains a symlink")
	}
	file := os.NewFile(uintptr(final), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() >= maximumSize {
		return nil, invalid("file must be regular, smaller than 1 MiB and not writable by other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, invalid("file must belong to the current user")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumSize))
	if err != nil || len(data) >= maximumSize {
		return nil, invalid("file cannot be read within its size limit")
	}
	return data, nil
}
