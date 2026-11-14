// SPDX-License-Identifier: Apache-2.0

// Package nievfs implements a virtual filesystem backend for Inazuma Eleven Victory Road
// (cpk_list.cfg.bin AES-256-CBC index + Criware XOR / CRILAYLA .cpk packs) over any rclone remote.
package nievfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/cache"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/dirtree"
	"github.com/rclone/rclone/fs/fspath"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/readers"
)

var errReadOnly = errors.New("nievfs: read-only virtual filesystem")

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "nievfs",
		Description: "Inazuma Eleven Victory Road VFS (cpk_list + Criware CPK stream)",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "remote",
			Help:     "Underlying remote or local path holding cpk_list.cfg.bin and packs/*.cpk.",
			Required: false,
		}},
	})
}

// Options defines configuration for nievfs.
type Options struct {
	Remote string `config:"remote"`
}

// Fs implements fs.Fs over an IEVR data directory (local, R2, S3, Drive, SFTP, HTTP).
type Fs struct {
	name     string
	root     string
	subRoot  string
	opt      Options
	f        fs.Fs
	wrapper  fs.Fs
	features *fs.Features
	dt       dirtree.DirTree
	modTime  time.Time

	cpkMu sync.Mutex
	cpks  map[string]*CpkReader
}

func resolveDataRemote(ctx context.Context, rawRemote string) (wrapped fs.Fs, subRoot string, err error) {
	cleaned := strings.TrimRight(rawRemote, "/")
	if cleaned == "" {
		cleaned = "/"
	}
	f, err := cache.Get(ctx, cleaned)
	if err == nil {
		if _, objErr := f.NewObject(ctx, "cpk_list.cfg.bin"); objErr == nil {
			return f, "", nil
		}
		if _, objErr := f.NewObject(ctx, "data/cpk_list.cfg.bin"); objErr == nil {
			subF, subErr := cache.Get(ctx, fspath.JoinRootPath(cleaned, "data"))
			if subErr == nil {
				return subF, "", nil
			}
		}
	}

	parsed, parseErr := fspath.Parse(cleaned)
	if parseErr == nil {
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for trim := 1; trim <= len(parts) && trim <= 8; trim++ {
			parentPath := strings.Join(parts[:len(parts)-trim], "/")
			candidate := parsed.Name + parentPath
			if parsed.Name == "" {
				candidate = "/" + parentPath
				if len(parts[0]) == 2 && parts[0][1] == ':' {
					candidate = parentPath
				}
			}
			pf, pErr := cache.Get(ctx, candidate)
			if pErr != nil {
				continue
			}
			if _, objErr := pf.NewObject(ctx, "cpk_list.cfg.bin"); objErr == nil {
				sub := strings.Join(parts[len(parts)-trim:], "/")
				return pf, CanonicalPath(sub), nil
			}
		}
	}
	if err != nil {
		return nil, "", fmt.Errorf("nievfs: failed to open underlying remote %q: %w", cleaned, err)
	}
	return nil, "", fmt.Errorf("nievfs: cpk_list.cfg.bin not found at %q", cleaned)
}

// NewFs mounts an IEVR VFS from an rclone remote or local data directory.
func NewFs(ctx context.Context, name, rpath string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return nil, err
	}
	remote := opt.Remote
	origRoot := rpath
	if remote == "" {
		remote = rpath
		rpath = ""
	}
	if strings.HasPrefix(remote, name+":") {
		return nil, errors.New("nievfs: remote cannot wrap itself")
	}
	if rpath != "" && rpath != "." {
		remote = fspath.JoinRootPath(remote, rpath)
	}

	wrapped, subRoot, err := resolveDataRemote(ctx, remote)
	if err != nil {
		return nil, err
	}

	cfgObj, err := wrapped.NewObject(ctx, "cpk_list.cfg.bin")
	if err != nil {
		return nil, fmt.Errorf("nievfs: missing cpk_list.cfg.bin: %w", err)
	}
	rc, err := cfgObj.Open(ctx)
	if err != nil {
		return nil, fmt.Errorf("nievfs: open cpk_list.cfg.bin: %w", err)
	}
	rawCfg, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return nil, fmt.Errorf("nievfs: read cpk_list.cfg.bin: %w", err)
	}

	entries, err := ParseCpkList(rawCfg)
	if err != nil {
		return nil, err
	}

	f := &Fs{
		name:    name,
		root:    origRoot,
		subRoot: subRoot,
		opt:     *opt,
		f:       wrapped,
		modTime: cfgObj.ModTime(ctx),
		cpks:    make(map[string]*CpkReader),
	}
	cache.PinUntilFinalized(f.f, f)
	f.features = (&fs.Features{
		CaseInsensitive:         false,
		DuplicateFiles:          false,
		ReadMimeType:            false,
		WriteMimeType:           false,
		CanHaveEmptyDirectories: true,
		BucketBased:             false,
	}).Fill(ctx, f).Mask(ctx, wrapped).WrapsFs(f, wrapped)

	dt := dirtree.New()
	singleObject := false
	for _, entry := range entries {
		vpath := entry.VirtualPath
		if subRoot != "" {
			if vpath == subRoot {
				singleObject = true
				dt = dirtree.New()
				dt.Add(&Object{
					f:       f,
					remote:  path.Base(vpath),
					vpath:   vpath,
					pack:    entry.PackName,
					size:    entry.FileSize,
					modTime: f.modTime,
				})
				break
			}
			if !strings.HasPrefix(vpath, subRoot+"/") {
				continue
			}
			vpath = strings.TrimPrefix(vpath, subRoot+"/")
		}
		dt.Add(&Object{
			f:       f,
			remote:  vpath,
			vpath:   entry.VirtualPath,
			pack:    entry.PackName,
			size:    entry.FileSize,
			modTime: f.modTime,
		})
	}
	if !singleObject && dt[""] == nil && len(entries) > 0 && subRoot != "" {
		return nil, fs.ErrorDirNotFound
	}
	dt.CheckParents("")
	dt.Sort()
	f.dt = dt
	if singleObject {
		return f, fs.ErrorIsFile
	}
	return f, nil
}

func (f *Fs) getCpkReader(ctx context.Context, packName string) (*CpkReader, fs.Object, error) {
	f.cpkMu.Lock()
	cached := f.cpks[packName]
	f.cpkMu.Unlock()

	obj, err := f.f.NewObject(ctx, "packs/"+packName)
	if err != nil {
		return nil, nil, fmt.Errorf("nievfs: pack %s not found: %w", packName, err)
	}
	if cached != nil {
		return cached, obj, nil
	}

	reader, err := ParseCpkFromReader(packName, func(offset uint64, length int) ([]byte, error) {
		end := int64(offset) + int64(length) - 1
		rc, err := obj.Open(ctx, &fs.RangeOption{Start: int64(offset), End: end})
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		buf := make([]byte, length)
		_, err = io.ReadFull(rc, buf)
		if err != nil {
			return nil, err
		}
		return buf, nil
	})
	if err != nil {
		return nil, nil, err
	}

	f.cpkMu.Lock()
	f.cpks[packName] = reader
	f.cpkMu.Unlock()
	return reader, obj, nil
}

// Name of the remote.
func (f *Fs) Name() string { return f.name }

// Root of the remote.
func (f *Fs) Root() string { return f.root }

// String returns a human-readable description.
func (f *Fs) String() string { return fmt.Sprintf("nievfs %q", f.name) }

// Features returns optional features.
func (f *Fs) Features() *fs.Features { return f.features }

// Precision returns ModTime precision.
func (f *Fs) Precision() time.Duration { return time.Second }

// Hashes returns supported hashes.
func (f *Fs) Hashes() hash.Set { return hash.Set(hash.None) }

// UnWrap returns the wrapped fs.Fs.
func (f *Fs) UnWrap() fs.Fs { return f.f }

// WrapFs returns the wrapping fs.Fs.
func (f *Fs) WrapFs() fs.Fs { return f.wrapper }

// SetWrapper sets the wrapping fs.Fs.
func (f *Fs) SetWrapper(wrapper fs.Fs) { f.wrapper = wrapper }

// List returns entries in a logical VFS directory.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	dir = strings.Trim(CanonicalPath(dir), "/")
	entries, ok := f.dt[dir]
	if !ok {
		return nil, fs.ErrorDirNotFound
	}
	return slices.Clone(entries), nil
}

// NewObject resolves a logical VFS file.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	remote = CanonicalPath(remote)
	_, entry := f.dt.Find(remote)
	if entry == nil {
		return nil, fs.ErrorObjectNotFound
	}
	o, ok := entry.(*Object)
	if !ok {
		return nil, fs.ErrorNotAFile
	}
	return o, nil
}

// Put returns read-only error.
func (f *Fs) Put(context.Context, io.Reader, fs.ObjectInfo, ...fs.OpenOption) (fs.Object, error) {
	return nil, errReadOnly
}

// Mkdir returns read-only error.
func (f *Fs) Mkdir(context.Context, string) error { return errReadOnly }

// Rmdir returns read-only error.
func (f *Fs) Rmdir(context.Context, string) error { return errReadOnly }

// Object represents a logical file served from loose tree or a .cpk pack.
type Object struct {
	f       *Fs
	remote  string
	vpath   string
	pack    string
	size    int64
	modTime time.Time
}

// Fs returns parent Fs.
func (o *Object) Fs() fs.Info { return o.f }

// String returns object description.
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns remote-relative path.
func (o *Object) Remote() string { return o.remote }

// Size returns logical uncompressed size when known.
func (o *Object) Size() int64 { return o.size }

// ModTime returns cpk_list timestamp.
func (o *Object) ModTime(context.Context) time.Time { return o.modTime }

// SetModTime returns read-only error.
func (o *Object) SetModTime(context.Context, time.Time) error { return errReadOnly }

// Storable reports storable status.
func (o *Object) Storable() bool { return true }

// Hash returns unsupported.
func (o *Object) Hash(context.Context, hash.Type) (string, error) { return "", hash.ErrUnsupported }

// Update returns read-only error.
func (o *Object) Update(context.Context, io.Reader, fs.ObjectInfo, ...fs.OpenOption) error {
	return errReadOnly
}

// Remove returns read-only error.
func (o *Object) Remove(context.Context) error { return errReadOnly }

type decryptReadCloser struct {
	inner     io.ReadCloser
	key       uint32
	encrypted bool
	offset    uint64
}

func (d *decryptReadCloser) Read(p []byte) (int, error) {
	n, err := d.inner.Read(p)
	if n > 0 && d.encrypted {
		DecryptBlock(p[:n], d.offset, d.key)
		d.offset += uint64(n)
	}
	return n, err
}

func (d *decryptReadCloser) Close() error {
	return d.inner.Close()
}

// Open opens and streams the logical VFS asset (range-capable on uncompressed pack assets).
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	if o.pack == "" {
		rel := strings.TrimPrefix(o.vpath, "data/")
		obj, err := o.f.f.NewObject(ctx, rel)
		if err != nil {
			obj, err = o.f.f.NewObject(ctx, o.vpath)
			if err != nil {
				return nil, err
			}
		}
		return obj.Open(ctx, options...)
	}

	cpkReader, packObj, err := o.f.getCpkReader(ctx, o.pack)
	if err != nil {
		return nil, err
	}
	relInCpk := strings.TrimPrefix(o.vpath, "data/")
	entry, ok := cpkReader.ByPath[o.vpath]
	if !ok {
		entry, ok = cpkReader.ByPath[relInCpk]
		if !ok {
			return nil, fs.ErrorObjectNotFound
		}
	}

	logicalSize := int64(entry.ExtractSize)
	if logicalSize <= 0 {
		logicalSize = int64(entry.Size)
	}

	var offset, limit int64 = 0, -1
	for _, option := range options {
		switch x := option.(type) {
		case *fs.SeekOption:
			offset = x.Offset
		case *fs.RangeOption:
			offset, limit = x.Decode(logicalSize)
		}
	}
	if offset < 0 {
		offset = 0
	}

	if !entry.Compressed {
		if entry.Size == 0 {
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
		if uint64(offset) >= entry.Size {
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
		avail := int64(entry.Size) - offset
		if limit < 0 || limit > avail {
			limit = avail
		}
		if limit == 0 {
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
		start := int64(entry.Offset) + offset
		end := start + limit - 1
		rc, err := packObj.Open(ctx, &fs.RangeOption{Start: start, End: end})
		if err != nil {
			return nil, err
		}
		return &decryptReadCloser{
			inner:     rc,
			key:       cpkReader.Key,
			encrypted: cpkReader.Encrypted,
			offset:    uint64(start),
		}, nil
	}

	rc, err := packObj.Open(ctx, &fs.RangeOption{
		Start: int64(entry.Offset),
		End:   int64(entry.Offset + entry.Size - 1),
	})
	if err != nil {
		return nil, err
	}
	raw := make([]byte, entry.Size)
	_, err = io.ReadFull(rc, raw)
	_ = rc.Close()
	if err != nil {
		return nil, err
	}
	if cpkReader.Encrypted {
		DecryptBlock(raw, entry.Offset, cpkReader.Key)
	}
	plain := raw
	if len(raw) >= 8 && bytes.Equal(raw[:8], []byte("CRILAYLA")) {
		plain, err = DecompressCriLayla(raw)
		if err != nil {
			return nil, err
		}
	}
	if offset >= int64(len(plain)) {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	slice := plain[offset:]
	if limit >= 0 && limit < int64(len(slice)) {
		slice = slice[:limit]
	}
	return readers.NewLimitedReadCloser(io.NopCloser(bytes.NewReader(slice)), int64(len(slice))), nil
}

var (
	_ fs.Fs        = (*Fs)(nil)
	_ fs.UnWrapper = (*Fs)(nil)
	_ fs.Wrapper   = (*Fs)(nil)
	_ fs.Object    = (*Object)(nil)
)
