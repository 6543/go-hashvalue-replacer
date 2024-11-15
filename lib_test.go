package hashvalue_replacer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func blake2bHash(salt []byte, data string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func noHash(_ []byte, data string) string {
	return data
}

func TestReader(t *testing.T) {
	salt := []byte("test-salt")
	opts := Options{
		Mask: "********",
	}

	tc := []struct {
		name    string
		log     string
		secrets []string
		expect  string
	}{{
		name:    "single line passwords",
		log:     `this IS secret: password`,
		secrets: []string{"password", " IS "},
		expect:  `this********secret: ********`,
	}, {
		name:    "secret with one newline",
		log:     "start log\ndone\nnow\nan\nmulti line secret!! ;)",
		secrets: []string{"an\nmulti line secret!!"},
		expect:  "start log\ndone\nnow\n******** ;)",
	}, {
		name:    "secret with multiple lines with no match",
		log:     "start log\ndone\nnow\nan\nmulti line secret!! ;)",
		secrets: []string{"Test\nwith\n\ntwo new lines"},
		expect:  "start log\ndone\nnow\nan\nmulti line secret!! ;)",
	}, {
		name:    "secret with multiple lines with match",
		log:     "start log\ndone\nnow\nan\nmulti line secret!! ;)\nwith\ntwo\n\nnewlines",
		secrets: []string{"an\nmulti line secret!!", "two\n\nnewlines"},
		expect:  "start log\ndone\nnow\n******** ;)\nwith\n********",
	}, {
		name:    "also support other unicode chars",
		log:     "мультибайт\nтекст",
		secrets: []string{"мульти"},
		expect:  "********байт\nтекст",
	}, {
		name:    "loop detection of mask already in input",
		log:     "already masked ********",
		secrets: []string{"********"},
		expect:  "already masked ********",
	}, {
		name:    "log starts with zeros",
		log:     "000000000\nword",
		secrets: []string{"\nwo"},
		expect:  "000000000********rd",
	}}

	hashes := []struct {
		name   string
		hashFn HashAlgorithm
	}{{
		name:   "no hash",
		hashFn: noHash,
	}, {
		name:   "blake2b hash",
		hashFn: blake2bHash,
	}}

	for _, hash := range hashes {
		t.Run(hash.name, func(t *testing.T) {
			opts.Hash = hash.hashFn
			for _, c := range tc {
				t.Run(c.name, func(t *testing.T) {
					hashes, lengths := ValuesToArgs(opts.Hash, salt, c.secrets)
					reader, err := NewReader(strings.NewReader(c.log), salt, hashes, lengths, opts)
					assert.NoError(t, err)

					// Read and process the entire log
					var buf bytes.Buffer
					_, err = io.Copy(&buf, reader)
					assert.NoError(t, err)

					assert.EqualValues(t, c.expect, buf.String())
				})
			}
		})
	}
}

func BenchmarkReader(b *testing.B) {
	salt := []byte("test-salt")
	opts := Options{
		Hash: func(salt []byte, data string) string {
			h := sha256.New()
			h.Write(salt)
			h.Write([]byte(data))
			return string(h.Sum(nil))
		},
		Mask: "********",
	}

	testCases := []struct {
		name    string
		log     string
		secrets []string
	}{
		{
			name:    "single line",
			log:     "this is a log with secret password and more text",
			secrets: []string{"password"},
		},
		{
			name:    "multi line",
			log:     "log start\nthis is a multi\nline secret\nlog end",
			secrets: []string{"multi\nline secret"},
		},
		{
			name:    "many secrets",
			log:     "log with many secrets: secret1 secret2 secret3 secret4 secret5",
			secrets: []string{"secret1", "secret2", "secret3", "secret4", "secret5"},
		},
		{
			name:    "large log",
			log:     "start " + string(bytes.Repeat([]byte("test secret test "), 1000)) + " end",
			secrets: []string{"secret"},
		},
		{
			name:    "large log no match",
			log:     "start " + string(bytes.Repeat([]byte("test secret test "), 1000)) + " end",
			secrets: []string{"XXXXXXX"},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			input := []byte(tc.log)
			hashes, lengths := ValuesToArgs(opts.Hash, salt, tc.secrets)
			inputReader := bytes.NewReader(input)
			reader, _ := NewReader(inputReader, salt, hashes, lengths, opts)

			b.ResetTimer()
			b.SetBytes(int64(len(input)))

			for i := 0; i < b.N; i++ {
				_, _ = io.Copy(io.Discard, reader)
				b.StopTimer()
				_, _ = inputReader.Seek(0, io.SeekStart)
				b.StartTimer()
			}
		})
	}
}

func BenchmarkReaderNoHash(b *testing.B) {
	salt := []byte{}
	opts := Options{
		Hash: func(_ []byte, data string) string {
			return data
		},
		Mask: "********",
	}

	testCases := []struct {
		name    string
		log     string
		secrets []string
	}{
		{
			name:    "single line",
			log:     "this is a log with secret password and more text",
			secrets: []string{"password"},
		},
		{
			name:    "multi line",
			log:     "log start\nthis is a multi\nline secret\nlog end",
			secrets: []string{"multi\nline secret"},
		},
		{
			name:    "many secrets",
			log:     "log with many secrets: secret1 secret2 secret3 secret4 secret5",
			secrets: []string{"secret1", "secret2", "secret3", "secret4", "secret5"},
		},
		{
			name:    "large log",
			log:     "start " + string(bytes.Repeat([]byte("test secret test "), 1000)) + " end",
			secrets: []string{"secret"},
		},
		{
			name:    "large log no match",
			log:     "start " + string(bytes.Repeat([]byte("test secret test "), 1000)) + " end",
			secrets: []string{"XXXXXXX"},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			input := []byte(tc.log)
			hashes, lengths := ValuesToArgs(opts.Hash, salt, tc.secrets)
			inputReader := bytes.NewReader(input)
			reader, _ := NewReader(inputReader, salt, hashes, lengths, opts)

			b.ResetTimer()
			b.SetBytes(int64(len(input)))

			for i := 0; i < b.N; i++ {
				_, _ = io.Copy(io.Discard, reader)
				b.StopTimer()
				_, _ = inputReader.Seek(0, io.SeekStart)
				b.StartTimer()
			}
		})
	}
}

// cpu: AMD Ryzen 9 7940HS
// BenchmarkReaderNoHash/single_line-16         	 1000000	      1041 ns/op	  46.10 MB/s	     368 B/op	      36 allocs/op
// BenchmarkReaderNoHash/multi_line-16          	 1083728	      1001 ns/op	  44.97 MB/s	     617 B/op	      27 allocs/op
// BenchmarkReaderNoHash/many_secrets-16        	  795691	      1351 ns/op	  45.88 MB/s	     513 B/op	      35 allocs/op
// BenchmarkReaderNoHash/large_log-16           	    2574	    460755 ns/op	  36.92 MB/s	  292468 B/op	   25451 allocs/op
// BenchmarkReaderNoHash/large_log_no_match-16  	    2552	    467957 ns/op	  36.35 MB/s	  275242 B/op	   26447 allocs/op

func FuzzReader(f *testing.F) {
	// Add initial corpus
	seeds := []struct {
		input  string
		secret string
	}{
		{"simple text", "simple"},
		{"simple text", "NON"},
		{"line1\nline2\nline3", "line2"},
		{"test\npass\nword\n", "pass\nword"},
		{"multiline\nsecret\nhere", "multiline\nsecret"},
		{"overlap1overlap2", "overlap"},
		{strings.Repeat("a", 1000), "aaa"},
		{"мультибайт\nтекст", "мульти"},
	}

	for _, seed := range seeds {
		f.Add(seed.input, seed.secret)
	}

	// Fuzzing function
	f.Fuzz(func(t *testing.T, input string, secret string) {
		// Skip empty inputs
		if len(secret) < 3 {
			return
		}

		if secret == "*" {
			// we expect an noop
			return
		}

		// Setup reader
		secrets := []string{secret}
		opts := Options{
			Hash: noHash,
			Mask: "*",
		}

		hashes, lengths := ValuesToArgs(opts.Hash, nil, secrets)
		inputReader := strings.NewReader(input)
		reader, err := NewReader(inputReader, nil, hashes, lengths, opts)
		// Test reader creation
		if err != nil {
			t.Fatal("reader creation failed:", err)
		}
		if len(secrets) == 0 {
			if reader != inputReader {
				t.Fatal("empty secrets should return original reader")
			}
			return
		}

		// Read and verify output
		var output bytes.Buffer
		buf := make([]byte, 1024)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				output.Write(chunk)
			}
			if err != nil {
				break
			}
		}

		result := output.String()

		// Invariant checks
		if len(result) == 0 && len(input) > 0 {
			t.Error("empty output for non-empty input")
		}

		// Check that all secrets are properly masked
		for _, secret := range secrets {
			if strings.Contains(result, secret) {
				t.Errorf("unmasked secret found in output: %q (input: %q)", secret, input)
			}
		}
	})
}
