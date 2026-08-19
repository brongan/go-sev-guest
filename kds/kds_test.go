// Copyright 2022 Google LLC
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

package kds

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-sev-guest/abi"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestProductCertChainURL(t *testing.T) {
	got := ProductCertChainURL(abi.VcekReportSigner, "Milan")
	want := "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
	if got != want {
		t.Errorf("ProductCertChainURL(\"Milan\") = %q, want %q", got, want)
	}
}

func TestVCEKCertURL(t *testing.T) {
	hwid := make([]byte, abi.ChipIDSize)
	hwid[0] = 0xfe
	hwid[abi.ChipIDSize-1] = 0xc0
	got := VCEKCertURL("Milan", hwid, TCBVersionV0(0))
	want := "https://kdsintf.amd.com/vcek/v1/Milan/fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0?blSPL=0&teeSPL=0&snpSPL=0&ucodeSPL=0"
	if got != want {
		t.Errorf("VCEKCertURL(\"Milan\", %v, 0) = %q, want %q", hwid, got, want)
	}
}

func TestParseProductBaseURL(t *testing.T) {
	tcs := []struct {
		name        string
		url         string
		wantProduct string
		wantURL     *url.URL
		wantErr     string
	}{
		{
			name:        "happy path",
			url:         ProductCertChainURL(abi.VcekReportSigner, "Milan"),
			wantProduct: "Milan",
			wantURL: &url.URL{
				Scheme: "https",
				Host:   "kdsintf.amd.com",
				Path:   "cert_chain", // The vcek/v1/Milan part is expected to be trimmed.
			},
		},
		{
			name:    "bad host",
			url:     "https://fakekds.com/vcek/v1/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL host \"fakekds.com\", want \"kdsintf.amd.com\"",
		},
		{
			name:    "bad scheme",
			url:     "http://kdsintf.amd.com/vcek/v1/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL scheme \"http\", want \"https\"",
		},
		{
			name:    "bad path",
			url:     "https://kdsintf.amd.com/vcek/v2/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL path \"/vcek/v2/Milan/cert_chain\", want prefix \"/vcek/v1/\"",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseBaseProductURL(tc.url)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("parseBaseProductURL(%q) = _, _, %v, want %q", tc.url, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(parsed.simpleURL, tc.wantURL); diff != "" {
					t.Errorf("parseBaseProductURL(%q) returned unexpected diff (-want +got):\n%s", tc.url, diff)
				}
				if parsed.productLine != tc.wantProduct {
					t.Errorf("parseBaseProductURL(%q) = %q, _, _ want %q", tc.url, parsed.productLine, tc.wantProduct)
				}
			}
		})
	}
}

func TestParseProductCertChainURL(t *testing.T) {
	tests := []struct {
		key     abi.ReportSigner
		product string
		wantKey CertFunction
	}{
		{
			key:     abi.VcekReportSigner,
			product: "Milan",
			wantKey: VcekCertFunction,
		},
		{
			key:     abi.VlekReportSigner,
			product: "Milan",
			wantKey: VlekCertFunction,
		},
	}
	for _, tc := range tests {
		url := ProductCertChainURL(tc.key, tc.product)
		got, key, err := ParseProductCertChainURL(url)
		if err != nil {
			t.Fatalf("ParseProductCertChainURL(%q) = _, _, %v, want nil", tc.product, err)
		}
		if got != tc.product || key != tc.wantKey {
			t.Errorf("ProductCertChainURL(%q) = %q, %v, nil want %q, %v", url, got, key, tc.product, tc.wantKey)
		}
	}
}

func TestParseVCEKCertURL(t *testing.T) {
	hwid := make([]byte, abi.ChipIDSize)
	hwidhex := hex.EncodeToString(hwid)
	tcs := []struct {
		name    string
		url     string
		want    VCEKCert
		wantErr string
	}{
		{
			name: "happy path",
			url:  VCEKCertURL("Milan", hwid, TCBVersionV0(0)),
			want: func() VCEKCert {
				c := VCEKCertProduct("Milan")
				c.HWID = hwid
				c.TCB = 0
				return c
			}(),
		},
		{
			name:    "bad query format",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?ha;ha", hwidhex),
			wantErr: "invalid AMD KDS URL query \"ha;ha\": invalid semicolon separator in query",
		},
		{
			name:    "bad query key",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?fakespl=4", hwidhex),
			wantErr: "unexpected KDS TCB version URL argument \"fakespl\"",
		},
		{
			name:    "bad query argument numerical",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=-4", hwidhex),
			wantErr: "invalid KDS TCB version URL argument value \"-4\", want a value 0-255",
		},
		{
			name:    "bad query argument numerical",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=alpha", hwidhex),
			wantErr: "invalid KDS TCB version URL argument value \"alpha\", want a value 0-255",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVCEKCertURL(tc.url)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ParseVCEKCertURL(%q) = _, %v, want %q", tc.url, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(got, tc.want); diff != "" {
					t.Errorf("ParseVCEKCertURL(%q) returned unexpected diff (-want +got):\n%s", tc.url, diff)
				}
			}
		})
	}
}

func TestProductName(t *testing.T) {
	tcs := []struct {
		name  string
		input *pb.SevProduct
		want  string
	}{
		{
			name: "nil",
			want: "Milan-B1",
		},
		{
			name: "unknown",
			input: &pb.SevProduct{
				MachineStepping: &wrapperspb.UInt32Value{Value: 0x1A},
			},
			want: "badstepping",
		},
		{
			name: "Milan-B0",
			input: &pb.SevProduct{
				Name: pb.SevProduct_SEV_PRODUCT_MILAN,
			},
			want: "UnknownStepping",
		},
		{
			name: "Milan-B0",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0},
			},
			want: "Milan-B0",
		},
		{
			name: "Genoa-FF",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0xff},
			},
			want: "badstepping",
		},
		{
			name: "unknown milan stepping",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "unmappedMilanStepping",
		},
		{
			name: "unknown genoa stepping",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "unmappedGenoaStepping",
		},
		{
			name: "unknown",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_UNKNOWN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "Unknown",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProductName(tc.input); got != tc.want {
				t.Errorf("ProductName(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseProductName(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		key     abi.ReportSigner
		want    *pb.SevProduct
		wantErr string
	}{
		{
			name:    "empty",
			wantErr: "unknown product name",
		},
		{
			name:    "Too big",
			input:   "Milan-100",
			wantErr: "unknown product name",
		},
		{
			name:  "happy path Genoa",
			input: "Genoa-B1",
			want: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 1},
			},
		},
		{
			name:    "bad revision Milan",
			input:   "Milan-A1",
			wantErr: "unknown product name",
		},
		{
			name:  "vlek products have no stepping",
			input: "Genoa",
			key:   abi.VlekReportSigner,
			want: &pb.SevProduct{
				Name: pb.SevProduct_SEV_PRODUCT_GENOA,
			},
		},
		{
			name:    "Unhandled report signer",
			input:   "ignored",
			key:     abi.NoneReportSigner,
			wantErr: "internal: unhandled reportSigner",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseProductName(tc.input, tc.key)
			if (err == nil && tc.wantErr != "") || (err != nil && (tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Fatalf("ParseProductName(%v) errored unexpectedly: %v, want %q", tc.input, err, tc.wantErr)
			}
			if tc.wantErr == "" {
				if diff := cmp.Diff(got, tc.want, protocmp.Transform()); diff != "" {
					t.Fatalf("ParseProductName(%v) = %v, want %v\nDiff: %s", tc.input, got, tc.want, diff)
				}
			}
		})
	}
}

func TestTCBVersionV0(t *testing.T) {
	tcb, err := ComposeTCBVersionV0(1, 2, 3, 4, 5, 6, 7, 8)
	if err != nil {
		t.Fatalf("ComposeTCBVersionV0 failed: %v", err)
	}
	if tcb.BlSpl() != 1 || tcb.TeeSpl() != 2 || tcb.Spl4() != 3 || tcb.Spl5() != 4 ||
		tcb.Spl6() != 5 || tcb.Spl7() != 6 || tcb.SnpSpl() != 7 || tcb.UcodeSpl() != 8 {
		t.Errorf("TCBVersionV0 accessors failed: got bl=%d tee=%d spl4=%d spl5=%d spl6=%d spl7=%d snp=%d ucode=%d",
			tcb.BlSpl(), tcb.TeeSpl(), tcb.Spl4(), tcb.Spl5(), tcb.Spl6(), tcb.Spl7(), tcb.SnpSpl(), tcb.UcodeSpl())
	}

	// Range validation tests (0-127 for bl, tee, spl4-7, snp; 0-255 for ucode).
	invalidCases := []struct {
		name                                        string
		bl, tee, spl4, spl5, spl6, spl7, snp, ucode uint8
	}{
		{"BlSpl > 127", 128, 0, 0, 0, 0, 0, 0, 0},
		{"TeeSpl > 127", 0, 128, 0, 0, 0, 0, 0, 0},
		{"Spl4 > 127", 0, 0, 128, 0, 0, 0, 0, 0},
		{"Spl5 > 127", 0, 0, 0, 128, 0, 0, 0, 0},
		{"Spl6 > 127", 0, 0, 0, 0, 128, 0, 0, 0},
		{"Spl7 > 127", 0, 0, 0, 0, 0, 128, 0, 0},
		{"SnpSpl > 127", 0, 0, 0, 0, 0, 0, 128, 0},
	}
	for _, tc := range invalidCases {
		if _, err := ComposeTCBVersionV0(tc.bl, tc.tee, tc.spl4, tc.spl5, tc.spl6, tc.spl7, tc.snp, tc.ucode); err == nil {
			t.Errorf("ComposeTCBVersionV0(%s) expected error, got nil", tc.name)
		}
	}

	// UcodeSpl can be up to 255 without error.
	if _, err := ComposeTCBVersionV0(127, 127, 127, 127, 127, 127, 127, 255); err != nil {
		t.Errorf("ComposeTCBVersionV0 with ucode=255 returned unexpected error: %v", err)
	}

	// Component-wise LE tests across all 8 fields.
	base, _ := ComposeTCBVersionV0(10, 10, 10, 10, 10, 10, 10, 10)
	if !base.LE(base) {
		t.Errorf("expected base.LE(base) to be true")
	}

	higherFields := []struct {
		name                                        string
		bl, tee, spl4, spl5, spl6, spl7, snp, ucode uint8
	}{
		{"BlSpl", 11, 10, 10, 10, 10, 10, 10, 10},
		{"TeeSpl", 10, 11, 10, 10, 10, 10, 10, 10},
		{"Spl4", 10, 10, 11, 10, 10, 10, 10, 10},
		{"Spl5", 10, 10, 10, 11, 10, 10, 10, 10},
		{"Spl6", 10, 10, 10, 10, 11, 10, 10, 10},
		{"Spl7", 10, 10, 10, 10, 10, 11, 10, 10},
		{"SnpSpl", 10, 10, 10, 10, 10, 10, 11, 10},
		{"UcodeSpl", 10, 10, 10, 10, 10, 10, 10, 11},
	}
	for _, tc := range higherFields {
		higher, _ := ComposeTCBVersionV0(tc.bl, tc.tee, tc.spl4, tc.spl5, tc.spl6, tc.spl7, tc.snp, tc.ucode)
		if !base.LE(higher) {
			t.Errorf("expected base.LE(higher for %s) to be true", tc.name)
		}
		if higher.LE(base) {
			t.Errorf("expected higher.LE(base for %s) to be false", tc.name)
		}
	}
}
