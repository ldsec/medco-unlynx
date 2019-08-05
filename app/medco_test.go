package main

import (
	"encoding/base64"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3/log"
	"testing"
)

func TestReplicateRoster(t *testing.T) {
	sksBase64 := []string{"af457bd25e2401e20f92ef1f1564a4716e3a1b10be3ab3c5f9cd0a1c81f34f07", "4203b0fb2dbe5ccb8cff358d5be42fd8612e5269b5d6ad0d22c613371641fe04", "8d1b40debecfb8324cbe303129ef7e9ebd66b5ce660adeed7bbdabc753837908"}
	pubksBase64 := []string{"2fb70ecd3347316b2c1fa130b3ef18be60daa4d3d3cc66a8bbb409c57a1d66c8", "b46f755195b594c6fd056036f276b00197da04801c01f32fb055f6abf606a2b1", "071e379405706e0cab11c4ad2509180f36859b8cfdc88c3cf68882fe266571ea"}
	ephemeralBase64 := [][]string{{"mmTfA84oZHkURF0wBeu3nQRJT6sjvkFhCSwE/TbAmwo=", "fSyKyMkTfyYEc01uDFLHaEqlaaQUdOb8sV3sNfqyFwI=", "Pz2h3j50HEMNq2txvRZgsf+r48j57ONeMdm1MqLSfgc="},
		{"87hq8MgGbKy9Oa0XNezfQ7B69Ky6IdiutkTZACRC5As=", "70hhKYYfwYugN7fCobPWHApxQIRzpmk/vOtO5CftDwE=", "LZ74i54VwEUZXkJGqb0YQoGMfXm/XAbjHoT0phvNnAs="},
		{"EXmTRaSldsQviB+o9OyG9PSJPFgMzrNxHqkFmL8GCgU=", "pMfvHlZ4M9t5RXF9n0/aPN/qMoSQxVghYovy5ihhcQ4=", "BiDdI1Xg1MgGmDDXP/MXhqaQPVUDGIb54yfBLzsuhQc="}}

	sks := make([]kyber.Scalar, 0)
	pubks := make([]kyber.Point, 0)
	ephemeral := make([][]kyber.Scalar, 0)
	for i := 0; i < len(sksBase64); i++ {
		tmpSk, err := encoding.StringHexToScalar(libunlynx.SuiTe, sksBase64[i])
		assert.NoError(t, err)
		sks = append(sks, tmpSk)

		tmpPk, err := encoding.StringHexToPoint(libunlynx.SuiTe, pubksBase64[i])
		assert.NoError(t, err)
		pubks = append(pubks, tmpPk)

		tmpEp := make([]kyber.Scalar, 0)
		for j := 0; j < len(sksBase64); j++ {
			secret := libunlynx.SuiTe.Scalar()
			b, err := base64.StdEncoding.DecodeString(ephemeralBase64[i][j])
			assert.NoError(t, err)

			err = secret.UnmarshalBinary(b)
			assert.NoError(t, err)
			tmpEp = append(tmpEp, secret)
		}
		ephemeral = append(ephemeral, tmpEp)
	}

	expectedSums := addEphemeralCollumnWise(ephemeral)

	newSks, newPubks, newEphemeral := replicateNodes(sks, ephemeral, 3)

	for i := 0; i < len(newSks); i++ {
		log.LLvl1("Node", i, ":")

		strSk, err := encoding.ScalarToStringHex(libunlynx.SuiTe, newSks[i])
		assert.NoError(t, err)
		log.LLvl1("Secret Key [", i, "]:", strSk)

		strPk, err := encoding.PointToStringHex(libunlynx.SuiTe, newPubks[i])
		assert.NoError(t, err)
		log.LLvl1("Public Key [", i, "]:", strPk)

		log.LLvl1("Ephemeral [", i, "]:")
		for j := 0; j < len(newEphemeral[i]); j++ {
			strEp, err := libunlynx.SerializeScalar(newEphemeral[i][j])
			assert.NoError(t, err)
			log.LLvl1(strEp)
		}
		log.LLvl1("")
	}

	// check pubKeys
	aggregateExpected := pubks[0]
	for i := 1; i < len(pubks); i++ {
		aggregateExpected = aggregateExpected.Add(aggregateExpected, pubks[i])
	}
	aggregate := newPubks[0]
	for i := 1; i < len(newPubks); i++ {
		aggregate = aggregate.Add(aggregate, newPubks[i])
	}
	assert.Equal(t, aggregateExpected.String(), aggregate.String())

	// check pubKeys
	aggregateExpected = libunlynx.SuiTe.Point().Mul(sks[0], nil)
	for i := 1; i < len(sks); i++ {
		aggregateExpected = aggregateExpected.Add(aggregateExpected, libunlynx.SuiTe.Point().Mul(sks[i], nil))
	}
	aggregate = libunlynx.SuiTe.Point().Mul(newSks[0], nil)
	for i := 1; i < len(newSks); i++ {
		aggregate = aggregate.Add(aggregate, libunlynx.SuiTe.Point().Mul(newSks[i], nil))
	}
	assert.Equal(t, aggregateExpected.String(), aggregate.String())

	// check ephemeral
	realSums := addEphemeralCollumnWise(newEphemeral)
	for i := 0; i < len(realSums); i++ {
		if i < len(expectedSums) {
			assert.Equal(t, expectedSums[i].String(), realSums[i].String())
		} else {
			assert.Equal(t, expectedSums[0].String(), realSums[i].String())
		}

	}
}

func addEphemeralCollumnWise(data [][]kyber.Scalar) []kyber.Scalar {
	expectedSums := make([]kyber.Scalar, len(data[0]))
	copy(expectedSums, data[0])
	for i := 1; i < len(data); i++ {
		for j := 0; j < len(data[i]); j++ {
			tmp := expectedSums[j].Clone()
			tmp = tmp.Add(tmp, data[i][j])
			expectedSums[j] = tmp.Clone()
		}
	}
	return expectedSums
}

func TestA(t *testing.T) {
	original := [][]string{{"mmTfA84oZHkURF0wBeu3nQRJT6sjvkFhCSwE/TbAmwo=", "mmTfA84oZHkURF0wBeu3nQRJT6sjvkFhCSwE/TbAmwo=", "mmTfA84oZHkURF0wBeu3nQRJT6sjvkFhCSwE/TbAmwo="},
		{"g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM=", "g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM=", "g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM="},
		{"kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI=", "kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI=", "kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI="},
	}

	ephemeralOriginal := make([][]kyber.Scalar, 0)
	for i := 0; i < 3; i++ {
		tmpEp := make([]kyber.Scalar, 0)
		for j := 0; j < 3; j++ {
			secret := libunlynx.SuiTe.Scalar()
			b, err := base64.StdEncoding.DecodeString(original[i][j])
			assert.NoError(t, err)

			err = secret.UnmarshalBinary(b)
			assert.NoError(t, err)
			tmpEp = append(tmpEp, secret)
		}
		ephemeralOriginal = append(ephemeralOriginal, tmpEp)
	}


	ephemeralBase64 := [][]string{{"g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM=", "g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM=", "g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM=", "g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM=", "g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM=", "g2tRgPpPSQUof8bTsGSHJj39k7wfvDO09zYUQHIc7wM="},
		{"kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI=", "kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI=", "kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI=", "kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI=", "kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI=", "kZfKbXNLx44DclYGXawjNIucNpMFMF3HUFma8peqwAI="},
		{"wlbJypglVA3fkmBYE8rFZl8Dr_10kLejTPoeg0nxIA0=", "kKgk29szNahtc5Z73UYfKwP1cDd2GKipy0b4osL7TQg=", "iMAz5R7czVEgOqYzF-ffnVb9p11NkZ6wcAJ7mB9xyQM=", "uH4IKWqzyK86ZBKy141NSs-F-9DFF9JODFGGuj3xAA0=", "OVn8xa9BrDnxfdJz49JOU9FofuhubRKdq6QVyyeQrQQ=", "NatxyFXMuH-DlGXG2PbrZqrgU9AeNddTLP-kBN1fHwg="},
		{"QgA4gGco55QRQCDE01R7MEdO51Zw4-VdWb_NOZQUOAI=", "kWwMzxAszD7krG4OUH8ifHx4dwu5Y-dHw7K73qZFLgU=", "V2WHqbfim3Ij7Swi8OJsqRteypdD-0-9YjKv04E3Mgw=", "8LaiX_aiKhi4n0LS-csVr0TdiKG9vBaCdnIwrZ8ruA8=", "dOC-401CkCDD2BQgrOkEWfkwihCih1UUY3DnOfxZGg0=", "kgStQLzNRUpZmVANELP0FHkK0PMJuPMsKl4XAYFFdQs="},
		{"gbAJFxHsD-EvlRXPmGebrI_GlUlGT9SfL9LqooWZYAQ=", "B5NXEq64mM7BNbY-zm-cAgnSdNrweEV0taoXupjkNg8=", "-rz7Xm2awemets5_n47_c7v4yfPHjP6KqVNStYqwIgk=", "L8UtOI2phvLvROgJfmiTY7aQZAYXHw0tQDpNzXZrLg0=", "ZFCV1rw3Y_XZLoRES396j_UEok283P7nKOJjX-OaVAA=", "1Hnq3rAk7scipG01wjLEcp24Gdi3nIT4fNmyAQMBaQw="},
		{"AjHK_tZRK07KeL7nY166bs4wIw34-s-_M6AsndMg4gY=", "TGRCAWjW7nOtJ5GtxqiXHXwJ8o0DyWz7xIc4wTSa6A0=", "rlUec6QySyMIA7P9PIxK99b0EsLKpFRojKOH2wpnfQE=", "nRHy_BTvDm_eNA_ochx_ajpVZjKJyktjRi4AyOI3tAA=", "dq6E4C3Q1oFcW-n6CKnIdkSqpGRW7NrH0TSjmC87fwg=", "2eLB1T8wnJfBqyhtFwLR2EOlEQ9DNPLnNfWU9dUZngo="},
	}

	ephemeral := make([][]kyber.Scalar, 0)
	for i := 0; i < 6; i++ {
		tmpEp := make([]kyber.Scalar, 0)
		for j := 0; j < 6; j++ {
			secret := libunlynx.SuiTe.Scalar()
			b, err := base64.URLEncoding.DecodeString(ephemeralBase64[i][j])
			assert.NoError(t, err)

			err = secret.UnmarshalBinary(b)
			assert.NoError(t, err)
			tmpEp = append(tmpEp, secret)
		}
		ephemeral = append(ephemeral, tmpEp)
	}

	originalSums := addEphemeralCollumnWise(ephemeralOriginal)
	log.LLvl1(originalSums)

	realSums := addEphemeralCollumnWise(ephemeral)
	log.LLvl1(realSums)

}
