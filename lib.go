package hashvalue_replacer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
)

type HashAlgorithm func(salt []byte, data string) string

type Options struct {
	Hash HashAlgorithm
	Mask string
}

var ErrorInvalidLengths = errors.New("invalid window lengths")

type Reader struct {
	reader    *bufio.Reader
	salt      []byte
	hashes    map[string]struct{}
	lengths   []int
	options   Options
	buffer    *bytes.Buffer
	maxLength int
}

func ValuesToArgs(hashFn HashAlgorithm, salt []byte, values []string) (hashes []string, lengths []int) {
	hm := make(map[string]struct{})
	lm := make(map[int]struct{})
	for _, value := range values {
		hm[hashFn(salt, value)] = struct{}{}
		lm[len(value)] = struct{}{}
	}
	for k := range hm {
		hashes = append(hashes, k)
	}
	for k := range lm {
		lengths = append(lengths, k)
	}
	return hashes, lengths
}

func NewReader(rd io.Reader, salt []byte, hashes []string, lengths []int, opts Options) (io.Reader, error) {
	if len(hashes) == 0 {
		return rd, nil
	}

	sort.Sort(sort.Reverse(sort.IntSlice(lengths)))
	if len(lengths) == 0 || lengths[0] == 0 {
		return nil, fmt.Errorf("%w: the reader needs at least one window size bigger than zero", ErrorInvalidLengths)
	}

	r := &Reader{
		reader:    bufio.NewReader(rd),
		salt:      salt,
		lengths:   lengths,
		options:   opts,
		hashes:    make(map[string]struct{}, len(hashes)),
		buffer:    &bytes.Buffer{},
		maxLength: lengths[0],
	}

	for _, hash := range hashes {
		r.hashes[hash] = struct{}{}
	}

	return r, nil
}

func (r *Reader) Read(p []byte) (n int, err error) {
	// If buffer is empty, read at least maxLength*2 bytes to ensure we can match patterns
	if r.buffer.Len() < r.maxLength*2 {
		for r.buffer.Len() < r.maxLength*2 {
			line, err := r.reader.ReadBytes('\n')
			if err != nil && err != io.EOF {
				return 0, err
			}
			if len(line) > 0 {
				r.buffer.Write(line)
			}
			if err == io.EOF {
				break
			}
		}
	}

	if r.buffer.Len() == 0 {
		return 0, io.EOF
	}

	data := r.buffer.Bytes()
	result := r.processData(data)

	n = copy(p, result)
	r.buffer.Reset()

	if n < len(result) {
		r.buffer.Write(result[n:])
	}

	return n, nil
}

func (r *Reader) processData(data []byte) []byte {
	result := make([]byte, 0, len(data))
	lastPos := 0
	dataLen := len(data)

	for i := 0; i < dataLen; {
		found := false
		// Try matching each length starting with longest
		for _, length := range r.lengths {
			if i+length > dataLen {
				continue
			}

			hash := r.options.Hash(r.salt, string(data[i:i+length]))
			if _, exists := r.hashes[hash]; exists {
				if i > lastPos {
					result = append(result, data[lastPos:i]...)
				}
				result = append(result, []byte(r.options.Mask)...)
				i += length
				lastPos = i
				found = true
				break
			}
		}
		if !found {
			i++
		}
	}

	if lastPos < dataLen {
		result = append(result, data[lastPos:]...)
	}

	return result
}
