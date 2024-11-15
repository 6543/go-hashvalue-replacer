package hashvalue_replacer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
	"unicode"

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

func FuzzReader(f *testing.F) {
	// Add initial corpus
	seeds := []struct {
		input   string
		secrets []string
	}{
		{"", []string{}},
		{"simple text", []string{"simple"}},
		{"line1\nline2\nline3", []string{"line2"}},
		{"test\npass\nword\n", []string{"pass\nword"}},
		{"multiline\nsecret\nhere", []string{"multiline\nsecret"}},
		{"overlap1overlap2", []string{"overlap1", "overlap2", "overlap"}},
		{strings.Repeat("a", 1000), []string{"aaa"}},
		{"мультибайт\nтекст", []string{"мульти"}},
	}

	for _, seed := range seeds {
		f.Add(seed.input, strings.Join(seed.secrets, "\n"))
	}

	// Fuzzing function
	f.Fuzz(func(t *testing.T, input, secretsList string) {
		// Skip empty inputs
		if len(input) == 0 && len(secretsList) == 0 {
			return
		}

		// Split secrets and filter invalid ones
		var secrets []string
		for _, s := range strings.Split(secretsList, "\n") {
			// Skip empty or very short secrets
			if len(s) <= 3 {
				continue
			}
			// Skip secrets containing only whitespace or control chars
			if strings.TrimSpace(s) == "" {
				continue
			}
			secrets = append(secrets, s)
		}

		// Setup reader
		opts := Options{
			Hash: noHash,
			Mask: "********",
		}

		salt := []byte("test-salt") // salt is ignored by noHash
		hashes, lengths := ValuesToArgs(opts.Hash, salt, secrets)
		inputReader := bytes.NewReader([]byte(input))
		reader, err := NewReader(inputReader, salt, hashes, lengths, opts)

		// Test reader creation
		if len(secrets) == 0 {
			if reader != inputReader {
				t.Fatal("empty secrets should return original reader")
			}
			return
		}
		if err != nil {
			t.Fatal("reader creation failed:", err)
		}

		// Read and verify output
		var output bytes.Buffer
		buf := make([]byte, 1024)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				// Verify mask replacement consistency
				chunk := buf[:n]
				maskCount := bytes.Count(chunk, []byte(opts.Mask))

				// Each secret should produce at most len(input)/len(secret) masks
				for _, secret := range secrets {
					maxPossibleMasks := len(input) / len(secret)
					if maskCount > maxPossibleMasks {
						t.Errorf("too many masks found: %d > %d (input: %q, secret: %q)",
							maskCount, maxPossibleMasks, input, secret)
					}
				}

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

		// Check that non-secret content is preserved when it should be
		nonSecretParts := strings.Split(input, "\n")
		for _, part := range nonSecretParts {
			isSecret := false
			for _, secret := range secrets {
				if strings.Contains(secret, part) {
					isSecret = true
					break
				}
			}
			if !isSecret && len(part) > 0 && !containsOnlySpecialChars(part) {
				// Check if this part should appear somewhere in output
				modifiedPart := strings.ReplaceAll(result, opts.Mask, "")
				if !strings.Contains(modifiedPart, part) && !strings.Contains(part, modifiedPart) {
					t.Errorf("non-secret content lost: %q (input: %q, result: %q)",
						part, input, result)
				}
			}
		}

		// Verify newline preservation
		inputNewlines := strings.Count(input, "\n")
		outputNewlines := strings.Count(result, "\n")
		if inputNewlines != outputNewlines {
			t.Errorf("newline count mismatch: got %d, want %d (input: %q, result: %q)",
				outputNewlines, inputNewlines, input, result)
		}
	})
}

func containsOnlySpecialChars(s string) bool {
	for _, r := range s {
		if !unicode.IsSpace(r) && !unicode.IsPunct(r) && !unicode.IsSymbol(r) {
			return false
		}
	}
	return true
}
