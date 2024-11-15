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

func TestReader(t *testing.T) {
	salt := []byte("test-salt")
	opts := Options{
		Hash: blake2bHash,
		Mask: "********",
	}

	tc := []struct {
		name    string
		log     string
		secrets []string
		expect  string
	}{{
		name:    "dont replace secrets with less than 4 chars",
		log:     "start log\ndone",
		secrets: []string{"", "d", "art"},
		expect:  "start log\ndone",
	}, {
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

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			// Filter secrets shorter than 3 chars
			var validSecrets []string
			for _, s := range c.secrets {
				if len(s) > 3 {
					validSecrets = append(validSecrets, s)
				}
			}

			hashes, lengths := ValuesToArgs(opts.Hash, salt, validSecrets)
			reader, err := NewReader(strings.NewReader(c.log), salt, hashes, lengths, opts)
			assert.NoError(t, err)

			// Read and process the entire log
			var buf bytes.Buffer
			_, err = io.Copy(&buf, reader)
			assert.NoError(t, err)

			assert.EqualValues(t, c.expect, buf.String())
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
			name:    "single_line",
			log:     "this is a log with secret password and more text",
			secrets: []string{"password"},
		},
		{
			name:    "multi_line",
			log:     "log start\nthis is a multi\nline secret\nlog end",
			secrets: []string{"multi\nline secret"},
		},
		{
			name:    "large_log",
			log:     "start " + string(bytes.Repeat([]byte("test secret test "), 1000)) + " end",
			secrets: []string{"secret"},
		},
		{
			name:    "many_secrets",
			log:     "log with many secrets: secret1 secret2 secret3 secret4 secret5",
			secrets: []string{"secret1", "secret2", "secret3", "secret4", "secret5"},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			hashes, lengths := ValuesToArgs(opts.Hash, salt, tc.secrets)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				reader, _ := NewReader(bytes.NewReader([]byte(tc.log)), salt, hashes, lengths, opts)
				out := make([]byte, len(tc.log)*2)
				for {
					_, err := reader.Read(out)
					if err != nil {
						break
					}
				}
			}
		})
	}
}
