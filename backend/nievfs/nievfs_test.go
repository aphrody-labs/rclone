// SPDX-License-Identifier: Apache-2.0

package nievfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
)

func TestDecryptBlockInvolutionAndWindow(t *testing.T) {
	key := KeyFromFilename("1d08dda99e8549431c6c7b459ed8deab.cpk")
	if key != 0xBD281847 {
		t.Fatalf("unexpected key: got %08x want bd281847", key)
	}
	orig := []byte("CPK \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b@UTFextra-bytes-12345")
	enc := append([]byte(nil), orig...)
	DecryptBlock(enc, 0, key)
	if bytes.Equal(enc, orig) {
		t.Fatal("DecryptBlock did not mutate buffer")
	}

	window := append([]byte(nil), enc[5:21]...)
	DecryptBlock(window, 5, key)
	if !bytes.Equal(window, orig[5:21]) {
		t.Fatalf("window decrypt mismatch: got %x want %x", window, orig[5:21])
	}

	DecryptBlock(enc, 0, key)
	if !bytes.Equal(enc, orig) {
		t.Fatal("involution mismatch")
	}
}

func TestCpkListKeyIVAndRealStream(t *testing.T) {
	key, iv := CpkListKeyIV()
	if binary.LittleEndian.Uint32(key[:4]) == cpkListKeyObf[0] || binary.LittleEndian.Uint32(iv[:4]) == cpkListIVObf[0] {
		t.Fatal("CpkListKeyIV did not deobfuscate key/iv")
	}

	dataDir := `C:\Program Files (x86)\Steam\steamapps\common\INAZUMA ELEVEN Victory Road\data`
	if _, err := os.Stat(filepath.Join(dataDir, "cpk_list.cfg.bin")); err != nil {
		t.Skip("Steam IEVR cpk_list.cfg.bin not present on host")
	}

	ctx := context.Background()
	f, err := NewFs(ctx, "nievfs", dataDir, configmap.Simple{})
	if err != nil {
		t.Fatalf("NewFs failed: %v", err)
	}
	entries, err := f.List(ctx, "")
	if err != nil || len(entries) == 0 {
		t.Fatalf("List root failed: len=%d err=%v", len(entries), err)
	}

	// Open a real packed file inside one of the encrypted .cpk archives via byte range.
	var picked *Object
	nf := f.(*Fs)
	for _, list := range nf.dt {
		for _, ent := range list {
			if obj, ok := ent.(*Object); ok && obj.pack != "" && obj.size > 64 {
				picked = obj
				break
			}
		}
		if picked != nil {
			break
		}
	}
	if picked == nil {
		t.Fatal("expected at least one packed object in real VFS")
	}
	rc, err := picked.Open(ctx, &fs.RangeOption{Start: 0, End: 15})
	if err != nil {
		t.Fatalf("picked.Open range failed for %s: %v", picked.Remote(), err)
	}
	head, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || len(head) != 16 {
		t.Fatalf("read 16 bytes from packed %s failed: len=%d err=%v", picked.Remote(), len(head), err)
	}
	t.Logf("streamed 16 bytes from %s (%s): %x", picked.Remote(), picked.pack, head)
}
