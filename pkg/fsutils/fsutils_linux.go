package fsutils // import "github.com/docker/docker/pkg/fsutils"

import (
	"fmt"
	"io/ioutil"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func locateDummyIfEmpty(path string) (string, error) {
	children, err := ioutil.ReadDir(path)
	if err != nil {
		return "", err
	}
	if len(children) != 0 {
		return "", nil
	}
	dummyFile, err := ioutil.TempFile(path, "fsutils-dummy")
	if err != nil {
		return "", err
	}
	name := dummyFile.Name()
	err = dummyFile.Close()
	return name, err
}

// SupportsDType returns whether the filesystem mounted on path supports d_type
func SupportsDType(path string) (bool, error) {
	// locate dummy so that we have at least one dirent
	dummy, err := locateDummyIfEmpty(path)
	if err != nil {
		return false, err
	}
	if dummy != "" {
		defer os.Remove(dummy)
	}

	visited := 0
	supportsDType := true
	fn := func(ent *unix.Dirent) bool {
		visited++
		if ent.Type == unix.DT_UNKNOWN {
			supportsDType = false
			// stop iteration
			return true
		}
		// continue iteration
		return false
	}
	if err = iterateReadDir(path, fn); err != nil {
		return false, err
	}
	if visited == 0 {
		return false, fmt.Errorf("did not hit any dirent during iteration %s", path)
	}
	return supportsDType, nil
}

func iterateReadDir(path string, fn func(*unix.Dirent) bool) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	fd := int(d.Fd())
	buf := make([]byte, 4096)
	for {
		nbytes, err := unix.ReadDirent(fd, buf)
		if err != nil {
			return err
		}
		if nbytes == 0 {
			break
		}
		for off := 0; off < nbytes; {
			ent := (*unix.Dirent)(unsafe.Pointer(&buf[off]))
			if stop := fn(ent); stop {
				return nil
			}
			off += int(ent.Reclen)
		}
	}
	return nil
}

// DoesMetacopy checks if the filesystem is going to optimize changes to
// metadata by using nodes marked with an "overlay.metacopy" attribute to avoid
// copying up a file from a lower layer unless/until its contents are being
// modified
func DoesMetacopy(d, mountOpts string) (bool, error) {
	td, err := ioutil.TempDir(d, "metacopy-check")
	if err != nil {
		return false, err
	}
	defer func() {
		if err := os.RemoveAll(td); err != nil {
			logrus.Warnf("Failed to remove check directory %v: %v", td, err)
		}
	}()

	// Make directories l1, l2, work, merged
	if err := os.MkdirAll(filepath.Join(td, "l1"), 0755); err != nil {
		return false, err
	}
	if err := ioutils.AtomicWriteFile(filepath.Join(td, "l1", "f"), []byte{0xff}, 0700); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Join(td, "l2"), 0755); err != nil {
		return false, err
	}
	if err := os.Mkdir(filepath.Join(td, "work"), 0755); err != nil {
		return false, err
	}
	if err := os.Mkdir(filepath.Join(td, "merged"), 0755); err != nil {
		return false, err
	}
	// Mount using the mandatory options and configured options
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", path.Join(td, "l1"), path.Join(td, "l2"), path.Join(td, "work"))
	flags, data := mount.ParseOptions(mountOpts)
	if data != "" {
		opts = fmt.Sprintf("%s,%s", opts, data)
	}
	if err := unix.Mount("overlay", filepath.Join(td, "merged"), "overlay", uintptr(flags), opts); err != nil {
		return false, errors.Wrap(err, "failed to mount overlay for metacopy check")
	}
	defer func() {
		if err := unix.Unmount(filepath.Join(td, "merged"), 0); err != nil {
			logrus.Warnf("Failed to unmount check directory %v: %v", filepath.Join(td, "merged"), err)
		}
	}()
	// Make a change that only impacts the inode, and check if the pulled-up copy is marked
	// as a metadata-only copy
	if err := os.Chmod(filepath.Join(td, "merged", "f"), 0600); err != nil {
		return false, errors.Wrap(err, "error changing permissions on file for metacopy check")
	}
	metacopy, err := system.Lgetxattr(filepath.Join(td, "l2", "f"), "trusted.overlay.metacopy")
	if err != nil {
		return false, errors.Wrap(err, "metacopy flag was not set on file in upper layer")
	}
	return metacopy != nil, nil
}

