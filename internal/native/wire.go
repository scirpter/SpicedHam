package native

import (
	"encoding/binary"
	"errors"

	"google.golang.org/protobuf/encoding/protowire"
)

type field struct {
	number protowire.Number
	kind   protowire.Type
	bytes  []byte
	value  uint64
}

type decoder struct {
	rest []byte
	err  error
}

func (d *decoder) next() (field, bool) {
	if d.err != nil || len(d.rest) == 0 {
		return field{}, false
	}
	number, kind, count := protowire.ConsumeTag(d.rest)
	if count < 0 {
		d.err = protowire.ParseError(count)
		return field{}, false
	}
	d.rest = d.rest[count:]
	result := field{number: number, kind: kind}
	switch kind {
	case protowire.BytesType:
		result.bytes, count = protowire.ConsumeBytes(d.rest)
	case protowire.VarintType:
		result.value, count = protowire.ConsumeVarint(d.rest)
	case protowire.Fixed32Type:
		var value uint32
		value, count = protowire.ConsumeFixed32(d.rest)
		result.value = uint64(value)
	case protowire.Fixed64Type:
		result.value, count = protowire.ConsumeFixed64(d.rest)
	default:
		count = protowire.ConsumeFieldValue(number, kind, d.rest)
	}
	if count < 0 {
		d.err = protowire.ParseError(count)
		return field{}, false
	}
	d.rest = d.rest[count:]
	return result, true
}

func (f field) asBytes() ([]byte, error) {
	if f.kind != protowire.BytesType {
		return nil, errors.New("native protobuf field has wrong wire type")
	}
	return f.bytes, nil
}

func (f field) asVarint() (uint64, error) {
	if f.kind != protowire.VarintType {
		return 0, errors.New("native protobuf field has wrong integer wire type")
	}
	return f.value, nil
}

func bytesField(target []byte, number protowire.Number, value []byte) []byte {
	target = protowire.AppendTag(target, number, protowire.BytesType)
	return protowire.AppendBytes(target, value)
}

func stringField(target []byte, number protowire.Number, value string) []byte {
	target = protowire.AppendTag(target, number, protowire.BytesType)
	return protowire.AppendString(target, value)
}

func varintField(target []byte, number protowire.Number, value uint64) []byte {
	target = protowire.AppendTag(target, number, protowire.VarintType)
	return protowire.AppendVarint(target, value)
}

func messageField(payload []byte, wanted protowire.Number) ([]byte, bool, error) {
	d := decoder{rest: payload}
	var result []byte
	var count, size int
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number == wanted {
			value, err := entry.asBytes()
			if err != nil {
				return nil, false, err
			}
			result = value
			count++
			size += len(value)
		}
	}
	if d.err != nil || count < 2 {
		return result, count != 0, d.err
	}
	// Singular protobuf messages merge, rather than replacing prior contents.
	// One occurrence borrows the original buffer; multiple occurrences need
	// exactly one lifetime buffer, sized before copying their wire streams.
	result = make([]byte, 0, size)
	d = decoder{rest: payload}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number == wanted {
			result = append(result, entry.bytes...)
		}
	}
	return result, true, nil
}

func uuidBytes(payload []byte) ([16]byte, error) {
	d := decoder{rest: payload}
	var result [16]byte
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number != 1 && entry.number != 2 {
			continue
		}
		if entry.kind != protowire.Fixed64Type {
			return result, errors.New("native UUID high/low values must be fixed64")
		}
		offset := int(entry.number-1) * 8
		binary.BigEndian.PutUint64(result[offset:offset+8], entry.value)
	}
	return result, d.err
}
