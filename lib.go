package hashvalue_replacer

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
)

type HashAlgorithm func(salt []byte, data []byte) []byte

type Options struct {
	Hash HashAlgorithm
	Mask string
}

var ErrorInvalidLengths = errors.New("invalid window lengths")

type Reader struct {
	reader    *bufio.Reader
	salt      []byte
	hashes    [][]byte
	lengths   []int
	options   Options
	buffer    *bytes.Buffer
	maxLength int
}

func ValuesToArgs(hashFn HashAlgorithm, salt []byte, values []string) (hashes [][]byte, lengths []int) {
	hm := make(map[string][]byte, len(values))
	lm := make(map[int]struct{}, len(values))

	for _, value := range values {
		hash := hashFn(salt, []byte(value))
		hm[hex.EncodeToString(hash)] = hash
		lm[len(value)] = struct{}{}
	}

	hashes = make([][]byte, 0, len(hm))
	for _, v := range hm {
		hashes = append(hashes, v)
	}
	lengths = make([]int, 0, len(lm))
	for k := range lm {
		lengths = append(lengths, k)
	}

	sort.Sort(sort.Reverse(sort.IntSlice(lengths)))
	return hashes, lengths
}

func NewReader(rd io.Reader, salt []byte, hashes [][]byte, lengths []int, opts Options) (io.Reader, error) {
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
		hashes:    hashes,
		buffer:    &bytes.Buffer{},
		maxLength: lengths[0],
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

			hash := r.options.Hash(r.salt, data[i:i+length])
			if r.hashMatch(hash) {
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

func (r *Reader) hashMatch(test []byte) bool {
	for i := range r.hashes {
		if bytes.Equal(test, r.hashes[i]) {
			return true
		}
	}
	return false
}
