// SPDX-License-Identifier: Apache-2.0

package nievfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strings"
)

const (
	utfBase        = 0x08
	utfMinTotal    = 0x20
	flagHasName    = 0x10
	flagHasDefault = 0x20
	flagRowStorage = 0x40
)

type utfTable struct {
	cols map[string]int
	rows [][]any
}

func readCStr(data []byte, base, off int) (string, error) {
	start := base + off
	if base < 0 || off < 0 || start >= len(data) {
		return "", errors.New("nievfs: @UTF string pool offset out of bounds")
	}
	sub := data[start:]
	if idx := bytes.IndexByte(sub, 0); idx >= 0 {
		return string(sub[:idx]), nil
	}
	return string(sub), nil
}

func colWireSize(t byte) (int, error) {
	switch t {
	case 0, 1:
		return 1, nil
	case 2, 3:
		return 2, nil
	case 4, 5, 8, 10:
		return 4, nil
	case 6, 7, 9, 11:
		return 8, nil
	case 12:
		return 16, nil
	default:
		return 0, fmt.Errorf("nievfs: unknown @UTF column type %d", t)
	}
}

func readUTFValue(data []byte, off int, colType byte, strPool int) (any, error) {
	ws, err := colWireSize(colType)
	if err != nil {
		return nil, err
	}
	if off < 0 || off+ws > len(data) {
		return nil, errors.New("nievfs: @UTF value out of bounds")
	}
	switch colType {
	case 0:
		return uint64(data[off]), nil
	case 1:
		return int64(int8(data[off])), nil
	case 2:
		return uint64(binary.BigEndian.Uint16(data[off : off+2])), nil
	case 3:
		return int64(int16(binary.BigEndian.Uint16(data[off : off+2]))), nil
	case 4:
		return uint64(binary.BigEndian.Uint32(data[off : off+4])), nil
	case 5:
		return int64(int32(binary.BigEndian.Uint32(data[off : off+4]))), nil
	case 6:
		return binary.BigEndian.Uint64(data[off : off+8]), nil
	case 7:
		return int64(binary.BigEndian.Uint64(data[off : off+8])), nil
	case 8, 9, 11, 12:
		return int64(0), nil
	case 10:
		strOff := int(binary.BigEndian.Uint32(data[off : off+4]))
		s, err := readCStr(data, strPool, strOff)
		if err != nil {
			return "", nil
		}
		return s, nil
	default:
		return nil, errors.New("nievfs: unsupported @UTF type")
	}
}

func parseUTF(data []byte) (*utfTable, error) {
	if len(data) < utfMinTotal || !bytes.Equal(data[:4], []byte("@UTF")) {
		return nil, errors.New("nievfs: invalid @UTF header")
	}
	rowsOffset := int(binary.BigEndian.Uint32(data[utfBase:])) + utfBase
	strPool := int(binary.BigEndian.Uint32(data[utfBase+4:])) + utfBase
	colCount := int(binary.BigEndian.Uint16(data[utfBase+16:]))
	rowStride := int(binary.BigEndian.Uint16(data[utfBase+18:]))
	rowCount := int(binary.BigEndian.Uint32(data[utfBase+20:]))

	if strPool > len(data) {
		return nil, errors.New("nievfs: @UTF string pool out of bounds")
	}

	type colDef struct {
		colType byte
		flags   byte
		name    string
		defVal  any
	}
	defs := make([]colDef, 0, colCount)
	cols := make(map[string]int, colCount)
	off := 0x20
	for i := 0; i < colCount; i++ {
		if off >= len(data) {
			return nil, errors.New("nievfs: @UTF truncated column schema")
		}
		flags := data[off]
		off++
		ct := flags & 0x0F
		ws, err := colWireSize(ct)
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("col_%d", i)
		if flags&flagHasName != 0 {
			if off+4 > len(data) {
				return nil, errors.New("nievfs: @UTF truncated column name offset")
			}
			no := int(binary.BigEndian.Uint32(data[off : off+4]))
			off += 4
			if resolved, err := readCStr(data, strPool, no); err == nil {
				name = resolved
			}
		}
		var defVal any
		if flags&flagHasDefault != 0 {
			defVal, err = readUTFValue(data, off, ct, strPool)
			if err != nil {
				return nil, err
			}
			off += ws
		}
		cols[name] = i
		defs = append(defs, colDef{colType: ct, flags: flags, name: name, defVal: defVal})
	}

	effRowsOff := rowsOffset
	if rowCount > 0 && rowsOffset+rowStride*rowCount > strPool {
		if strPool >= rowStride*rowCount {
			effRowsOff = strPool - rowStride*rowCount
		}
	}

	rows := make([][]any, rowCount)
	for r := 0; r < rowCount; r++ {
		cursor := effRowsOff + r*rowStride
		row := make([]any, colCount)
		for c, d := range defs {
			if d.flags&flagHasDefault != 0 {
				row[c] = d.defVal
			} else if d.flags&flagRowStorage != 0 {
				v, err := readUTFValue(data, cursor, d.colType, strPool)
				if err != nil {
					return nil, err
				}
				ws, _ := colWireSize(d.colType)
				cursor += ws
				row[c] = v
			} else if d.colType == 10 {
				row[c] = ""
			} else {
				row[c] = int64(0)
			}
		}
		rows[r] = row
	}
	return &utfTable{cols: cols, rows: rows}, nil
}

func (t *utfTable) getI64(row int, col string) (int64, bool) {
	ci, ok := t.cols[col]
	if !ok || row < 0 || row >= len(t.rows) {
		return 0, false
	}
	switch v := t.rows[row][ci].(type) {
	case int64:
		return v, true
	case uint64:
		return int64(v), true
	default:
		return 0, false
	}
}

func (t *utfTable) getStr(row int, col string) string {
	ci, ok := t.cols[col]
	if !ok || row < 0 || row >= len(t.rows) {
		return ""
	}
	s, _ := t.rows[row][ci].(string)
	return s
}

// CpkEntry describes one archived file inside a .cpk pack.
type CpkEntry struct {
	Path        string
	Offset      uint64
	Size        uint64
	ExtractSize uint64
	Compressed  bool
}

// CpkReader holds decrypted metadata and TOC entries for one CPK archive.
type CpkReader struct {
	PackName  string
	Encrypted bool
	Key       uint32
	ByPath    map[string]CpkEntry
	Entries   []CpkEntry
}

// RangeReadFn reads exact length bytes starting at offset from a CPK file.
type RangeReadFn func(offset uint64, length int) ([]byte, error)

// CanonicalPath normalizes virtual paths without leading or repeated slashes.
func CanonicalPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "/")
}

// ParseCpkFromReader reads and indexes only the header + TOC of a CPK archive.
func ParseCpkFromReader(packName string, read RangeReadFn) (*CpkReader, error) {
	probe, err := read(0, 16)
	if err != nil {
		return nil, err
	}
	if len(probe) < 16 {
		return nil, errors.New("nievfs: CPK header too short")
	}

	var isEnc bool
	var key uint32
	if !bytes.Equal(probe[:4], []byte("CPK ")) {
		candidates := []uint32{
			KeyFromFilename("002AB8F4-" + packName),
			KeyFromFilename(packName),
		}
		matched := false
		for _, k := range candidates {
			var test [4]byte
			copy(test[:], probe[:4])
			DecryptBlock(test[:], 0, k)
			if bytes.Equal(test[:], []byte("CPK ")) {
				isEnc = true
				key = k
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("nievfs: undecryptable CPK magic in %s", packName)
		}
	}

	readRegion := func(offset uint64, size int) ([]byte, error) {
		if size <= 0 || size > 64*1024*1024 {
			return nil, fmt.Errorf("nievfs: invalid CPK metadata size %d", size)
		}
		buf, err := read(offset, size)
		if err != nil {
			return nil, err
		}
		if len(buf) != size {
			return nil, fmt.Errorf("nievfs: short CPK range read: got %d want %d", len(buf), size)
		}
		if isEnc {
			DecryptBlock(buf, offset, key)
		}
		return buf, nil
	}

	hdrBox, err := readRegion(0, 16)
	if err != nil {
		return nil, err
	}
	hdrTableSize := int(binary.LittleEndian.Uint32(hdrBox[8:12]))
	hdrData, err := readRegion(0, 16+hdrTableSize)
	if err != nil {
		return nil, err
	}
	hdrUTF, err := parseUTF(hdrData[16:])
	if err != nil {
		return nil, err
	}

	tocOffset, ok := hdrUTF.getI64(0, "TocOffset")
	if !ok || tocOffset < 0 {
		return nil, errors.New("nievfs: missing TocOffset in CPK header")
	}
	contentOffset, ok := hdrUTF.getI64(0, "ContentOffset")
	if !ok || contentOffset < 0 || tocOffset < contentOffset {
		contentOffset = tocOffset
	}

	tocBox, err := readRegion(uint64(tocOffset), 16)
	if err != nil {
		return nil, err
	}
	tocTableSize := int(binary.LittleEndian.Uint32(tocBox[8:12]))
	tocData, err := readRegion(uint64(tocOffset), 16+tocTableSize)
	if err != nil {
		return nil, err
	}
	tocUTF, err := parseUTF(tocData[16:])
	if err != nil {
		return nil, err
	}

	entries := make([]CpkEntry, 0, len(tocUTF.rows))
	byPath := make(map[string]CpkEntry, len(tocUTF.rows))
	for i := range tocUTF.rows {
		fname := tocUTF.getStr(i, "FileName")
		dname := tocUTF.getStr(i, "DirName")
		foff, _ := tocUTF.getI64(i, "FileOffset")
		fsize, _ := tocUTF.getI64(i, "FileSize")
		esize, _ := tocUTF.getI64(i, "ExtractSize")
		absOff := foff + contentOffset
		if absOff < 0 || fsize < 0 {
			continue
		}
		virt := CanonicalPath(path.Join(dname, fname))
		entry := CpkEntry{
			Path:        virt,
			Offset:      uint64(absOff),
			Size:        uint64(fsize),
			ExtractSize: uint64(esize),
			Compressed:  esize != fsize && fsize > 0,
		}
		entries = append(entries, entry)
		byPath[virt] = entry
	}

	return &CpkReader{
		PackName:  packName,
		Encrypted: isEnc,
		Key:       key,
		ByPath:    byPath,
		Entries:   entries,
	}, nil
}

// CpkListEntry describes one logical entry mapped in cpk_list.cfg.bin.
type CpkListEntry struct {
	VirtualPath string
	PackName    string
	FileSize    int64
}

// ParseCpkList parses an encrypted or decrypted cpk_list.cfg.bin T2B payload.
func ParseCpkList(raw []byte) ([]CpkListEntry, error) {
	if clear, err := DecryptCpkList(raw); err == nil {
		if entries, err := parseT2BCpkList(clear); err == nil && len(entries) > 0 {
			return entries, nil
		}
	}
	viola := make([]byte, len(raw))
	copy(viola, raw)
	DecryptBlock(viola, 0, violaFixedKey)
	if entries, err := parseT2BCpkList(viola); err == nil && len(entries) > 0 {
		return entries, nil
	}
	if entries, err := parseT2BCpkList(raw); err == nil && len(entries) > 0 {
		return entries, nil
	}
	return nil, errors.New("nievfs: unable to decrypt or parse cpk_list.cfg.bin")
}

func parseT2BCpkList(data []byte) ([]CpkListEntry, error) {
	if len(data) < 16 {
		return nil, errors.New("nievfs: T2B header too short")
	}
	entriesCount := int32(binary.LittleEndian.Uint32(data[0:4]))
	strOff := int32(binary.LittleEndian.Uint32(data[4:8]))
	strLen := int32(binary.LittleEndian.Uint32(data[8:12]))
	strCount := int(int32(binary.LittleEndian.Uint32(data[12:16])))
	if entriesCount < 0 || strOff < 16 || strLen < 0 || int(strOff)+int(strLen) > len(data) {
		return nil, errors.New("nievfs: invalid T2B header bounds")
	}

	stringsMap := make(map[int32]string, strCount)
	pos := 0
	count := 0
	strEnd := int(strOff) + int(strLen)
	for pos < int(strLen) && count < strCount {
		start := int(strOff) + pos
		if start >= strEnd {
			break
		}
		sub := data[start:strEnd]
		nul := bytes.IndexByte(sub, 0)
		if nul < 0 {
			nul = len(sub)
		}
		s := string(sub[:nul])
		stringsMap[int32(pos)] = s
		pos += len(s) + 1
		count++
	}

	keyTableOff := ((strEnd + 15) / 16) * 16
	keyNames := make(map[uint32]string)
	if keyTableOff+16 <= len(data) {
		kLen := int(int32(binary.LittleEndian.Uint32(data[keyTableOff : keyTableOff+4])))
		if kLen > 0 && keyTableOff+kLen <= len(data) {
			kCnt := int(int32(binary.LittleEndian.Uint32(data[keyTableOff+4 : keyTableOff+8])))
			kStrOff := int(int32(binary.LittleEndian.Uint32(data[keyTableOff+8 : keyTableOff+12])))
			kStrLen := int(int32(binary.LittleEndian.Uint32(data[keyTableOff+12 : keyTableOff+16])))
			if kCnt <= kLen/8 && kStrOff < kLen {
				kBase := keyTableOff + 16
				sBlob := keyTableOff + kStrOff
				end := keyTableOff + kLen
				for i := 0; i < kCnt; i++ {
					ep := kBase + i*8
					if ep+8 > len(data) {
						break
					}
					crc := binary.LittleEndian.Uint32(data[ep : ep+4])
					sStart := int(int32(binary.LittleEndian.Uint32(data[ep+4 : ep+8])))
					if sStart >= 0 && sStart < kStrLen && sBlob+sStart <= end {
						sub := data[sBlob+sStart : end]
						nul := bytes.IndexByte(sub, 0)
						if nul < 0 {
							nul = len(sub)
						}
						keyNames[crc] = string(sub[:nul])
					}
				}
			}
		}
	}

	type t2bEntry struct {
		name string
		vars []any
	}
	flat := make([]t2bEntry, 0, entriesCount)
	cur := 16
	bufLen := int(strOff)
	for i := int32(0); i < entriesCount; i++ {
		if cur+5 > bufLen {
			break
		}
		crc := binary.LittleEndian.Uint32(data[cur : cur+4])
		paramCount := int(data[cur+4])
		cur += 5
		typeBytes := (paramCount + 3) / 4
		pTypes := make([]byte, 0, paramCount)
		for tbIdx := 0; tbIdx < typeBytes && cur < bufLen; tbIdx++ {
			tb := data[cur]
			cur++
			for k := 0; k < 4 && len(pTypes) < paramCount; k++ {
				pTypes = append(pTypes, (tb>>(2*k))&3)
			}
		}
		hdrTotal := 5 + typeBytes
		if hdrTotal%4 != 0 {
			cur += 4 - (hdrTotal % 4)
		}
		vars := make([]any, 0, paramCount)
		for j := 0; j < paramCount && cur+4 <= bufLen; j++ {
			ty := pTypes[j]
			switch ty {
			case 0:
				off := int32(binary.LittleEndian.Uint32(data[cur : cur+4]))
				if off != -1 {
					vars = append(vars, stringsMap[off])
				} else {
					vars = append(vars, "")
				}
			case 1:
				vars = append(vars, int32(binary.LittleEndian.Uint32(data[cur:cur+4])))
			default:
				vars = append(vars, nil)
			}
			cur += 4
		}
		name := keyNames[crc]
		flat = append(flat, t2bEntry{name: name, vars: vars})
	}

	out := make([]CpkListEntry, 0, len(flat))
	depth := 0
	for _, e := range flat {
		isEnd := len(e.vars) == 0 && (strings.HasSuffix(e.name, "_END") || e.name == "_PTREE" || strings.Contains(e.name, "_END_"))
		if isEnd {
			if depth > 0 {
				depth--
			}
			continue
		}
		isBegin := strings.HasSuffix(e.name, "_BEG") || strings.HasSuffix(e.name, "_BEGIN") ||
			strings.HasSuffix(e.name, "_BGN") || strings.Contains(e.name, "_BEG_") ||
			strings.Contains(e.name, "_BGN_") || strings.HasPrefix(e.name, "PTREE")
		if depth >= 1 && len(e.vars) >= 5 {
			dir, ok1 := e.vars[0].(string)
			file, ok2 := e.vars[1].(string)
			pack, ok3 := e.vars[3].(string)
			if ok1 && ok2 && ok3 {
				var fsize int64
				if sz, ok := e.vars[4].(int32); ok && sz > 0 {
					fsize = int64(sz)
				}
				virt := CanonicalPath(dir + "/" + file)
				if virt != "" {
					out = append(out, CpkListEntry{
						VirtualPath: virt,
						PackName:    pack,
						FileSize:    fsize,
					})
				}
			}
		}
		if isBegin {
			depth++
		}
	}
	return out, nil
}
