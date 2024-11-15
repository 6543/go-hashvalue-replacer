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

func TestSecretReplacer(t *testing.T) {
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
