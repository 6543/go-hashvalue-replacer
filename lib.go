package hashvalue_replacer

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type HashAlgorithm func(salt []byte, data []byte) []byte

type Options struct {
	Hash       HashAlgorithm
	Mask       string
	NumWorkers int
}

var ErrorInvalidLengths = errors.New("invalid window lengths")

type Reader struct {
	reader       *bufio.Reader
	readerCloser func() error
	salt         []byte
	hashes       [][]byte
	lengths      []int
	options      Options
	buffer       *bytes.Buffer
	maxLength    int
	chunkSize    int

	workers   []*worker
	workCh    chan *chunk
	resultCh  chan *chunk
	pending   map[int]*chunk
	nextChunk int
	mu        sync.Mutex
	wg        sync.WaitGroup
	closed    atomic.Bool
}

type chunk struct {
	id      int
	data    []byte
	overlap []byte
	isLast  bool
	result  []byte
}

type worker struct {
	r      *Reader
	stopCh chan struct{}
}

func ValuesToArgs(hashFn HashAlgorithm, salt []byte, values []string) (hashes [][]byte, lengths []int) {
	hm := make(map[string][]byte, len(values))
	lm := make(map[int]struct{}, len(values))

	for _, value := range values {
		value = strings.Trim(value, "\n")
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

func NewReader(rd io.ReadCloser, salt []byte, hashes [][]byte, lengths []int, opts Options) (io.ReadCloser, error) {
	if len(hashes) == 0 {
		return rd, nil
	}

	sort.Sort(sort.Reverse(sort.IntSlice(lengths)))
	if len(lengths) == 0 || lengths[0] == 0 {
		return nil, fmt.Errorf("%w: the reader needs at least one window size bigger than zero", ErrorInvalidLengths)
	}

	if opts.NumWorkers <= 0 {
		opts.NumWorkers = runtime.NumCPU()
	}

	r := &Reader{
		reader:       bufio.NewReader(rd),
		readerCloser: rd.Close,
		salt:         salt,
		lengths:      lengths,
		options:      opts,
		hashes:       hashes,
		buffer:       &bytes.Buffer{},
		maxLength:    lengths[0],
		chunkSize:    32 * 1024,
		workCh:       make(chan *chunk, opts.NumWorkers),
		resultCh:     make(chan *chunk, opts.NumWorkers),
		pending:      make(map[int]*chunk),
		workers:      make([]*worker, opts.NumWorkers),
	}

	// Start workers
	for i := 0; i < opts.NumWorkers; i++ {
		w := &worker{
			r:      r,
			stopCh: make(chan struct{}),
		}
		r.workers[i] = w
		r.wg.Add(1)
		go w.run()
	}

	return r, nil
}

func (w *worker) run() {
	defer w.r.wg.Done()
	for {
		select {
		case <-w.stopCh:
			return
		case chunk, ok := <-w.r.workCh:
			if !ok {
				return
			}
			data := append(chunk.data, chunk.overlap...)
			chunk.result = w.r.processData(data)
			if !chunk.isLast && len(chunk.result) > 0 {
				chunk.result = chunk.result[:len(chunk.data)]
			}
			select {
			case w.r.resultCh <- chunk:
			case <-w.stopCh:
				return
			}
		}
	}
}

func (r *Reader) Close() error {
	// Use atomic operation to ensure we only close once
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}

	r.mu.Lock()
	workers := r.workers
	r.workers = nil
	r.mu.Unlock()

	// Stop all workers
	for _, w := range workers {
		close(w.stopCh)
	}

	// Wait for workers to finish
	r.wg.Wait()

	r.mu.Lock()
	if r.workCh != nil {
		close(r.workCh)
		r.workCh = nil
	}
	if r.resultCh != nil {
		close(r.resultCh)
		r.resultCh = nil
	}
	r.pending = make(map[int]*chunk)
	r.nextChunk = 0
	r.mu.Unlock()

	// Close the underlying reader
	return r.readerCloser()
}

func (r *Reader) Read(p []byte) (n int, err error) {
	if r.closed.Load() {
		return 0, io.EOF
	}

	if r.buffer.Len() == 0 {
		if err := r.processNextChunk(); err != nil {
			if err == io.EOF {
				r.Close()
			}
			return 0, err
		}
	}

	n = copy(p, r.buffer.Bytes())
	r.buffer.Next(n)
	return n, nil
}

func (r *Reader) processNextChunk() error {
	if r.closed.Load() {
		return io.EOF
	}

	data := make([]byte, r.chunkSize)
	n, err := io.ReadFull(r.reader, data)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}

	isLast := err == io.EOF || err == io.ErrUnexpectedEOF
	if n == 0 && isLast {
		return io.EOF
	}

	overlap := make([]byte, r.maxLength)
	overlapN, err := r.reader.Read(overlap)
	if err != nil && err != io.EOF {
		return err
	}
	overlap = overlap[:overlapN]

	chunk := &chunk{
		id:      r.nextChunk,
		data:    data[:n],
		overlap: overlap,
		isLast:  isLast,
	}
	r.nextChunk++

	select {
	case r.workCh <- chunk:
	default:
		return fmt.Errorf("work channel full")
	}

	return r.processResults()
}

func (r *Reader) processResults() error {
	if r.closed.Load() {
		return io.EOF
	}

	result, ok := <-r.resultCh
	if !ok {
		return io.EOF
	}

	r.mu.Lock()
	r.pending[result.id] = result
	r.mu.Unlock()

	for {
		r.mu.Lock()
		chunk, exists := r.pending[len(r.buffer.Bytes())/r.chunkSize]
		r.mu.Unlock()

		if !exists {
			return nil
		}

		r.buffer.Write(chunk.result)
		r.mu.Lock()
		delete(r.pending, chunk.id)
		r.mu.Unlock()

		if chunk.isLast {
			r.Close()
			return nil
		}
	}
}

func (r *Reader) processData(data []byte) []byte {
	result := make([]byte, 0, len(data))
	lastPos := 0
	dataLen := len(data)

	for i := 0; i < dataLen; {
		found := false
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
