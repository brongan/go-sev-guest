// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// External test package so that seeds can use trust's real cert_chain bodies without an import cycle.
package kds_test

import (
	"encoding/pem"
	"testing"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
)

func FuzzParseProductCertChain(f *testing.F) {
	vcekPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testdata.VcekBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: testdata.VcekBytes})
	headerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X": "y"}, Bytes: testdata.VcekBytes})
	f.Add([]byte{})
	f.Add(trust.AskArkMilanVcekBytes)
	f.Add(trust.AskArkMilanVlekBytes)
	// Mutating the base64 armor rarely yields these, so seed one per checkForm and trailing-bytes rejection.
	f.Add(append(append([]byte{}, keyPEM...), vcekPEM...))
	f.Add(append(append([]byte{}, headerPEM...), vcekPEM...))
	f.Add(append(append([]byte{}, trust.AskArkMilanVcekBytes...), 'x'))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = kds.ParseProductCertChain(data)
	})
}
