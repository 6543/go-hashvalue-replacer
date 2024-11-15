package hashvalue_replacer

import (
	"bufio"
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
	reader  *bufio.Reader
	salt    []byte
	hashes  map[string]struct{}
	lengths []int
	options Options
	buffer  []byte
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

	// Sort lengths in descending order
	sort.Sort(sort.Reverse(sort.IntSlice(lengths)))

	if len(lengths) == 0 || lengths[0] == 0 {
		return nil, fmt.Errorf("%w: the reader needs at least one window size bigger than zero", ErrorInvalidLengths)
	}

	r := &Reader{
		reader:  bufio.NewReader(rd),
		salt:    salt,
		lengths: lengths,
		options: opts,
		hashes:  make(map[string]struct{}, len(hashes)),
		buffer:  make([]byte, lengths[0]),
	}

	for _, hash := range hashes {
		r.hashes[hash] = struct{}{}
	}

	return r, nil
}

func (r *Reader) Read(p []byte) (n int, err error) {
	line, err := r.reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return 0, err
	}
	if len(line) == 0 {
		return 0, err
	}

	var written int
	lastPos := 0
	lineLen := len(line)

outer:
	for i := 0; i <= lineLen-r.lengths[0]; i++ {
		// Check each length starting with largest
		for _, length := range r.lengths {
			if i+length > lineLen {
				continue
			}

			windowHash := r.options.Hash(r.salt, string(line[i:i+length]))
			if _, exists := r.hashes[windowHash]; exists {
				if i-lastPos > 0 {
					copied := copy(p[written:], line[lastPos:i])
					written += copied
				}
				copied := copy(p[written:], []byte(r.options.Mask))
				written += copied

				lastPos = i + length
				i += length - 1

				if written >= len(p) {
					return written, io.ErrShortBuffer
				}

				// we do not have to search for smaller windows to match
				continue outer
			}
		}
	}

	if lastPos < len(line) {
		copied := copy(p[written:], line[lastPos:])
		written += copied
	}

	return written, err
}
