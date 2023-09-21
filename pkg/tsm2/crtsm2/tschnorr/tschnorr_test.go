package tschnorr

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkDS(b *testing.B) {
	curveInit := curves.K256()
	scheme := NewScheme(curveInit)
	str := "test message test message test message test message test message test message test message test message test message test message "
	scheme.message = []byte(str)

	err := scheme.DKG()
	require.NoError(b, err, "failed in DKG")

	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		err = scheme.DS()
		require.NoError(b, err, "failed in DS")
	}
}
