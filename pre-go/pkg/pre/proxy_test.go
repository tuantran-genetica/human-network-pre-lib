package pre_test

import (
	"testing"

	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/pre"
	"github.com/lifenetwork-ai/proxy-recrypt-sdk/pre-go/pkg/testutils"
)

func BenchmarkReEncryption(b *testing.B) {
	scheme := pre.NewPreScheme()
	cipherText := testutils.GenerateMockSecondLevelCipherText(500)
	reKey := testutils.GenerateRandomG2Elem()
	for n := 0; n < b.N; n++ {
		scheme.Proxy.ReEncryption(cipherText, reKey)
	}
}
