// Native filesystem operations provide bounded advisory locks and durable replacements.
// Callers pass explicit target paths and fault injection; no user config is discovered.
package configstore

import (
	"context"
	"errors"
	"github.com/LanceSandino/aws-sso-profile-sync/internal/domain"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func lock(ctx context.Context, path string) (func(), error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if e := checkPath(path); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		if e := ctx.Err(); e != nil {
			f.Close()
			return nil, e
		}
		e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			// Keep the stable lock inode; unlinking it would let a third writer
			// obtain a different lock while another process still waits here.
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(e, syscall.EWOULDBLOCK) && !errors.Is(e, syscall.EAGAIN) {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-deadline.C:
			f.Close()
			return nil, domain.Fail("timed_out", "config advisory lock is held by another writer")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func atomic(path string, data []byte, mode os.FileMode, fault func(string) error) error {
	if e := checkPath(path); e != nil {
		return e
	}
	if e := fault("temp_create"); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".aws-sso-sync-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if info, err := os.Stat(path); err == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			if e = f.Chown(-1, int(st.Gid)); e != nil {
				return e
			}
		}
	}
	if e = f.Chmod(mode); e != nil {
		return e
	}
	if e = fault("temp_write"); e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = fault("temp_sync"); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = fault("rename"); e != nil {
		return e
	}
	if e = checkPath(path); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
