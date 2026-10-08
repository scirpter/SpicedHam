package apk

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

const noString = uint32(0xffffffff)

// The upstream XML parser deliberately accepts some broken Android archives.
// Package data used at a JNI boundary must not inherit its truncated chunks,
// invalid indices, unbounded string lengths or placeholder strings. Validate
// the binary structure first; preserve typed-string values without modifying
// the original archive or the manifest passed to the library.
func validateBinaryManifest(data []byte) (map[attributeLocation]string, error) {
	if len(data) < 8 || binary.LittleEndian.Uint16(data) != 3 {
		return nil, fmt.Errorf("expected a binary Android XML document")
	}
	header := int(binary.LittleEndian.Uint16(data[2:]))
	if header < 8 || header > len(data) || uint64(binary.LittleEndian.Uint32(data[4:])) != uint64(len(data)) {
		return nil, fmt.Errorf("invalid binary XML document length")
	}
	var pool binaryStringPool
	poolSeen := false
	resourceMapSeen := false
	elementCount := 0
	var overrides map[attributeLocation]string
	for position := header; position < len(data); {
		if len(data)-position < 8 {
			return nil, fmt.Errorf("truncated binary XML chunk header")
		}
		chunkType := binary.LittleEndian.Uint16(data[position:])
		chunkHeader := int(binary.LittleEndian.Uint16(data[position+2:]))
		chunkSize := int(binary.LittleEndian.Uint32(data[position+4:]))
		if chunkHeader < 8 || chunkSize < chunkHeader || chunkSize > len(data)-position {
			return nil, fmt.Errorf("invalid binary XML chunk at offset %d", position)
		}
		chunk := data[position : position+chunkSize]
		switch chunkType {
		case 1: // RES_STRING_POOL_TYPE
			if poolSeen || elementCount != 0 {
				return nil, fmt.Errorf("duplicate or misplaced XML string pool")
			}
			var err error
			pool, err = parseBinaryStringPool(chunk, chunkHeader)
			if err != nil {
				return nil, err
			}
			poolSeen = true
		case 0x180: // RES_XML_RESOURCE_MAP_TYPE
			if !poolSeen || resourceMapSeen || elementCount != 0 || chunkHeader != 8 || (chunkSize-8)%4 != 0 {
				return nil, fmt.Errorf("invalid binary XML resource map")
			}
			resourceMapSeen = true
		case 0x100, 0x101, 0x102, 0x103, 0x104:
			if !poolSeen || chunkHeader != 16 {
				return nil, fmt.Errorf("missing string pool or unsupported binary XML node header")
			}
			if !pool.validIndex(binary.LittleEndian.Uint32(chunk[12:]), true) {
				return nil, fmt.Errorf("invalid XML comment string index")
			}
			payload := chunk[chunkHeader:]
			if chunkType == 0x102 { // RES_XML_START_ELEMENT_TYPE
				if len(payload) < 20 {
					return nil, fmt.Errorf("truncated binary XML start element")
				}
				if !pool.validIndex(binary.LittleEndian.Uint32(payload), true) || !pool.validIndex(binary.LittleEndian.Uint32(payload[4:]), false) {
					return nil, fmt.Errorf("invalid XML element string index")
				}
				start := int(binary.LittleEndian.Uint16(payload[8:]))
				size := int(binary.LittleEndian.Uint16(payload[10:]))
				count := int(binary.LittleEndian.Uint16(payload[12:]))
				if start < 20 || size < 20 || start > len(payload) || count > (len(payload)-start)/size {
					return nil, fmt.Errorf("invalid binary XML attribute bounds")
				}
				for i := range count {
					attribute := payload[start+i*size : start+(i+1)*size]
					namespace := binary.LittleEndian.Uint32(attribute)
					name := binary.LittleEndian.Uint32(attribute[4:])
					raw := binary.LittleEndian.Uint32(attribute[8:])
					if !pool.validIndex(namespace, true) || !pool.validIndex(name, false) || !pool.validIndex(raw, true) || binary.LittleEndian.Uint16(attribute[12:]) != 8 {
						return nil, fmt.Errorf("invalid binary XML attribute value or index")
					}
					if attribute[15] == 3 { // TYPE_STRING
						index := binary.LittleEndian.Uint32(attribute[16:])
						if !pool.validIndex(index, false) {
							return nil, fmt.Errorf("invalid typed XML string index")
						}
						if raw != index {
							if overrides == nil {
								overrides = make(map[attributeLocation]string)
							}
							overrides[attributeLocation{elementCount, i}] = pool.stringAt(index)
						}
					}
				}
				elementCount++
			} else {
				minimum := 8
				if chunkType == 0x104 {
					minimum = 12
				}
				if len(payload) < minimum {
					return nil, fmt.Errorf("truncated binary XML node")
				}
				if !pool.validIndex(binary.LittleEndian.Uint32(payload), chunkType == 0x100 || chunkType == 0x101 || chunkType == 0x103) {
					return nil, fmt.Errorf("invalid XML node string index")
				}
				if chunkType != 0x104 && !pool.validIndex(binary.LittleEndian.Uint32(payload[4:]), false) {
					return nil, fmt.Errorf("invalid XML node name or namespace index")
				}
			}
		default:
			return nil, fmt.Errorf("unsupported binary XML chunk type %#x", chunkType)
		}
		position += chunkSize
	}
	if !poolSeen || elementCount == 0 {
		return nil, fmt.Errorf("binary XML has no string pool or elements")
	}
	return overrides, nil
}

type binaryStringPool struct {
	offsets []byte
	data    []byte
	utf8    bool
}

func parseBinaryStringPool(chunk []byte, header int) (binaryStringPool, error) {
	var pool binaryStringPool
	if header != 28 || len(chunk) < header {
		return pool, fmt.Errorf("unsupported binary XML string pool header")
	}
	count := uint64(binary.LittleEndian.Uint32(chunk[8:]))
	styles := uint64(binary.LittleEndian.Uint32(chunk[12:]))
	flags := binary.LittleEndian.Uint32(chunk[16:])
	start := uint64(binary.LittleEndian.Uint32(chunk[20:]))
	styleStart := uint64(binary.LittleEndian.Uint32(chunk[24:]))
	if flags & ^uint32(0x101) != 0 || count >= 2*1024*1024 || uint64(header)+4*(count+styles) > start || start > uint64(len(chunk)) {
		return pool, fmt.Errorf("invalid binary XML string pool bounds or flags")
	}
	end := uint64(len(chunk))
	if styles != 0 {
		if styleStart < start || styleStart > end {
			return pool, fmt.Errorf("invalid binary XML style pool bounds")
		}
		end = styleStart
	} else if styleStart != 0 {
		return pool, fmt.Errorf("unexpected binary XML style pool offset")
	}
	pool.offsets = chunk[header : uint64(header)+4*count]
	pool.data = chunk[start:end]
	pool.utf8 = flags&0x100 != 0
	for i := range count {
		offset := binary.LittleEndian.Uint32(pool.offsets[4*i:])
		if _, err := pool.stringBytes(offset); err != nil {
			return binaryStringPool{}, fmt.Errorf("invalid XML pool string %d: %w", i, err)
		}
	}
	return pool, nil
}

func (pool binaryStringPool) validIndex(index uint32, optional bool) bool {
	return optional && index == noString || uint64(index) < uint64(len(pool.offsets)/4)
}

func (pool binaryStringPool) stringAt(index uint32) string {
	offset := binary.LittleEndian.Uint32(pool.offsets[4*index:])
	data, _ := pool.stringBytes(offset) // Every string was validated above.
	if pool.utf8 {
		return string(data)
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	return string(utf16.Decode(units))
}

func (pool binaryStringPool) stringBytes(offset uint32) ([]byte, error) {
	if uint64(offset) >= uint64(len(pool.data)) {
		return nil, fmt.Errorf("string offset is out of bounds")
	}
	data := pool.data[offset:]
	if pool.utf8 {
		_, consumed, err := binaryStringLength(data, 1)
		if err != nil {
			return nil, err
		}
		length, prefix, err := binaryStringLength(data[consumed:], 1)
		if err != nil {
			return nil, err
		}
		data = data[consumed+prefix:]
		if uint64(length)+1 > uint64(len(data)) || data[length] != 0 || !utf8.Valid(data[:length]) {
			return nil, fmt.Errorf("invalid or unterminated UTF-8 string")
		}
		return data[:length], nil
	}
	length, consumed, err := binaryStringLength(data, 2)
	if err != nil {
		return nil, err
	}
	data = data[consumed:]
	bytes := uint64(length) * 2
	if bytes+2 > uint64(len(data)) || binary.LittleEndian.Uint16(data[bytes:]) != 0 {
		return nil, fmt.Errorf("invalid or unterminated UTF-16 string")
	}
	value := data[:bytes]
	for i := 0; i < len(value); i += 2 {
		unit := binary.LittleEndian.Uint16(value[i:])
		if unit >= 0xd800 && unit <= 0xdbff {
			i += 2
			if i >= len(value) {
				return nil, fmt.Errorf("unpaired UTF-16 high surrogate")
			}
			low := binary.LittleEndian.Uint16(value[i:])
			if low < 0xdc00 || low > 0xdfff {
				return nil, fmt.Errorf("unpaired UTF-16 high surrogate")
			}
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return nil, fmt.Errorf("unpaired UTF-16 low surrogate")
		}
	}
	return value, nil
}

func binaryStringLength(data []byte, width int) (uint32, int, error) {
	if len(data) < width {
		return 0, 0, fmt.Errorf("truncated string length")
	}
	if width == 1 {
		length := uint32(data[0])
		if length&0x80 == 0 {
			return length, 1, nil
		}
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("truncated extended string length")
		}
		return (length&0x7f)<<8 | uint32(data[1]), 2, nil
	}
	length := uint32(binary.LittleEndian.Uint16(data))
	if length&0x8000 == 0 {
		return length, 2, nil
	}
	if len(data) < 4 {
		return 0, 0, fmt.Errorf("truncated extended string length")
	}
	return (length&0x7fff)<<16 | uint32(binary.LittleEndian.Uint16(data[2:])), 4, nil
}
