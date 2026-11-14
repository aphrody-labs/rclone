// SPDX-License-Identifier: Apache-2.0

package nievfs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

const (
	violaFixedKey      uint32 = 0x1717E18E
	cpkListKeySeed     uint32 = 0x8A90ABA9
	cpkListIVSeed      uint32 = 0x4C801618
	criLaylaRawSize           = 0x100
	criLaylaMinCopyLen        = 3
	criLaylaMaxOutSize        = 256 * 1024 * 1024
)

var (
	cpkListKeyObf = [8]uint32{
		0x72C9CB21, 0x178BF2F9, 0x6450E29D, 0x4DA98CD1,
		0x1E908D53, 0x750DF696, 0x43D9A87A, 0x584FE242,
	}
	cpkListIVObf = [4]uint32{
		0x3F8E4B6D, 0xF0C9492F, 0x3844E69D, 0xB0CB1EE3,
	}
)

// KeyFromFilename derives the Criware XOR key from a CPK base filename.
func KeyFromFilename(name string) uint32 {
	return crc32.ChecksumIEEE([]byte(name))
}

func updateCRCState(seed uint32, k [4]byte) uint32 {
	crc := ^seed
	for i := 0; i < 4; i++ {
		idx := byte(crc&0xFF) ^ k[i]
		crc = (crc >> 8) ^ crc32.IEEETable[idx]
	}
	return ^crc
}

func computeXorByte(crc uint32, pos uint32) byte {
	baseShift := pos * 2
	r8 := (crc >> (baseShift + 8)) & 3
	r8 |= ((crc >> baseShift) & 0xFF) << 2 & 0xFF
	r8 = ((r8 << 2) & 0xFF) | ((crc >> (baseShift + 16)) & 3)
	r8 = ((r8 << 2) & 0xFF) | ((crc >> (baseShift + 24)) & 3)
	return byte(r8)
}

// DecryptBlock applies position-aware Criware XOR encryption/decryption in place.
func DecryptBlock(buf []byte, fileOffset uint64, key uint32) {
	if len(buf) == 0 {
		return
	}
	k := [4]byte{
		byte(key),
		byte(key >> 8),
		byte(key >> 16),
		byte(key >> 24),
	}

	i := 0
	length := len(buf)

	alignOffset := fileOffset & 3
	if alignOffset != 0 {
		curCRC := updateCRCState(uint32(fileOffset&^uint64(3)), k)
		alignCount := int(4 - alignOffset)
		if alignCount > length {
			alignCount = length
		}
		for j := 0; j < alignCount; j++ {
			pos := uint32((fileOffset + uint64(i)) & 3)
			buf[i] ^= computeXorByte(curCRC, pos)
			i++
		}
	}

	baseOffset := fileOffset + uint64(i)
	for i+4 <= length {
		c := updateCRCState(uint32(baseOffset), k)
		buf[i] ^= computeXorByte(c, 0)
		buf[i+1] ^= computeXorByte(c, 1)
		buf[i+2] ^= computeXorByte(c, 2)
		buf[i+3] ^= computeXorByte(c, 3)
		i += 4
		baseOffset += 4
	}

	if i < length {
		c := updateCRCState(uint32(baseOffset), k)
		var pos uint32
		for i < length {
			buf[i] ^= computeXorByte(c, pos)
			i++
			pos++
		}
	}
}

// CpkListKeyIV returns the AES-256 key and 16-byte IV for cpk_list.cfg.bin.
func CpkListKeyIV() ([32]byte, [16]byte) {
	var key [32]byte
	for i, w := range cpkListKeyObf {
		binary.LittleEndian.PutUint32(key[i*4:i*4+4], w)
	}
	DecryptBlock(key[:], 0, cpkListKeySeed)

	var iv [16]byte
	for i, w := range cpkListIVObf {
		binary.LittleEndian.PutUint32(iv[i*4:i*4+4], w)
	}
	DecryptBlock(iv[:], 0, cpkListIVSeed)
	return key, iv
}

// DecryptCpkList decrypts cpk_list.cfg.bin via AES-256-CBC (Steam builds).
func DecryptCpkList(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, errors.New("nievfs: cpk_list size is not a 16-byte AES block multiple")
	}
	key, iv := CpkListKeyIV()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(out, data)
	return out, nil
}

type criBitReader struct {
	ptr      int
	bitsLeft uint32
}

func (br *criBitReader) getNextBit(input []byte) (byte, error) {
	if br.bitsLeft == 0 {
		if br.ptr <= 0x10 {
			return 0, errors.New("nievfs: CRILAYLA bitstream exhausted (bit)")
		}
		br.ptr--
		br.bitsLeft = 7
	} else {
		br.bitsLeft--
	}
	return (input[br.ptr] >> br.bitsLeft) & 1, nil
}

func (br *criBitReader) read8(input []byte) (byte, error) {
	if br.ptr <= 0x10 {
		return 0, errors.New("nievfs: CRILAYLA bitstream exhausted (read8)")
	}
	br.ptr--
	if br.bitsLeft != 0 {
		extra := 8 - br.bitsLeft
		high := uint32(input[br.ptr+1] & ((1 << br.bitsLeft) - 1))
		low := (uint32(input[br.ptr]) >> br.bitsLeft) & ((1 << extra) - 1)
		return byte((high << extra) | low), nil
	}
	return input[br.ptr], nil
}

func (br *criBitReader) readMax8(bitCount uint32, input []byte) (byte, error) {
	if br.bitsLeft == 0 {
		if br.ptr <= 0x10 {
			return 0, errors.New("nievfs: CRILAYLA bitstream exhausted (readMax8 init)")
		}
		br.ptr--
		br.bitsLeft = 8
	}
	take1 := br.bitsLeft
	if bitCount < take1 {
		take1 = bitCount
	}
	br.bitsLeft -= take1
	res := (input[br.ptr] >> br.bitsLeft) & ((1 << take1) - 1)
	rem := bitCount - take1
	if rem == 0 {
		return res, nil
	}
	if br.ptr <= 0x10 {
		return 0, errors.New("nievfs: CRILAYLA bitstream exhausted (readMax8 cross)")
	}
	br.ptr--
	br.bitsLeft = 8
	br.bitsLeft -= rem
	low := (input[br.ptr] >> br.bitsLeft) & ((1 << rem) - 1)
	return (res << rem) | low, nil
}

func (br *criBitReader) read13(input []byte) (uint16, error) {
	var bitCount uint32 = 13
	if br.bitsLeft == 0 {
		if br.ptr <= 0x10 {
			return 0, errors.New("nievfs: CRILAYLA bitstream exhausted (read13 init)")
		}
		br.ptr--
		br.bitsLeft = 8
	}
	var out uint16
	for bitCount > 0 {
		take := br.bitsLeft
		if bitCount < take {
			take = bitCount
		}
		br.bitsLeft -= take
		chunk := uint16((input[br.ptr] >> br.bitsLeft) & ((1 << take) - 1))
		out = (out << take) | chunk
		bitCount -= take
		if bitCount > 0 {
			if br.ptr <= 0x10 {
				return 0, errors.New("nievfs: CRILAYLA bitstream exhausted (read13 loop)")
			}
			br.ptr--
			br.bitsLeft = 8
		}
	}
	return out, nil
}

// DecompressCriLayla decompresses a Criware CRILAYLA buffer.
func DecompressCriLayla(input []byte) ([]byte, error) {
	if len(input) < 0x10+criLaylaRawSize || !bytes.Equal(input[:8], []byte("CRILAYLA")) {
		return nil, errors.New("nievfs: invalid CRILAYLA header")
	}
	uncompSize := int(binary.LittleEndian.Uint32(input[8:12]))
	headerOff := int(binary.LittleEndian.Uint32(input[12:16]))
	rawStart := 0x10 + headerOff
	rawEnd := rawStart + criLaylaRawSize
	if headerOff < 0 || rawEnd > len(input) {
		return nil, errors.New("nievfs: CRILAYLA raw header out of bounds")
	}
	totalSize := criLaylaRawSize + uncompSize
	if uncompSize < 0 || totalSize > criLaylaMaxOutSize {
		return nil, errors.New("nievfs: CRILAYLA decompressed size exceeds 256 MiB")
	}
	out := make([]byte, totalSize)
	copy(out[:criLaylaRawSize], input[rawStart:rawEnd])
	if uncompSize == 0 {
		return out, nil
	}

	br := criBitReader{ptr: rawStart, bitsLeft: 0}
	writePos := totalSize
	for writePos > criLaylaRawSize {
		flag, err := br.getNextBit(input)
		if err != nil {
			return nil, err
		}
		if flag == 0 {
			b, err := br.read8(input)
			if err != nil {
				return nil, err
			}
			writePos--
			out[writePos] = b
			continue
		}

		rawOff, err := br.read13(input)
		if err != nil {
			return nil, err
		}
		offset := int(rawOff) + criLaylaMinCopyLen
		length := criLaylaMinCopyLen

		lvl2, err := br.readMax8(2, input)
		if err != nil {
			return nil, err
		}
		length += int(lvl2)
		if lvl2 == 3 {
			lvl3, err := br.readMax8(3, input)
			if err != nil {
				return nil, err
			}
			length += int(lvl3)
			if lvl3 == 7 {
				lvl5, err := br.readMax8(5, input)
				if err != nil {
					return nil, err
				}
				length += int(lvl5)
				if lvl5 == 31 {
					for {
						lvl8, err := br.read8(input)
						if err != nil {
							return nil, err
						}
						length += int(lvl8)
						if length > writePos-criLaylaRawSize {
							return nil, errors.New("nievfs: CRILAYLA backref overflow")
						}
						if lvl8 != 0xFF {
							break
						}
					}
				}
			}
		}

		if length > writePos-criLaylaRawSize {
			return nil, errors.New("nievfs: CRILAYLA backref exceeds start")
		}
		dstStart := writePos - length
		srcEnd := writePos + offset
		if srcEnd > totalSize {
			return nil, errors.New("nievfs: CRILAYLA backref source out of bounds")
		}
		if offset >= length {
			copy(out[dstStart:writePos], out[srcEnd-length:srcEnd])
		} else {
			for i := writePos - 1; i >= dstStart; i-- {
				out[i] = out[i+offset]
			}
		}
		writePos = dstStart
	}
	return out, nil
}
