package servicesmedco_test

import (
	"encoding/base64"
	"github.com/lca1/medco-unlynx/services"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"strconv"
	"sync"
	"testing"
)

func getParam(nbServers int) (*onet.Roster, *onet.LocalTest) {

	log.SetDebugVisible(1)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entity list
	_, el, _ := local.GenTree(nbServers, true)

	// get query parameters
	return el, local
}

func getClients(nbHosts int, el *onet.Roster) []*servicesmedco.API {
	clients := make([]*servicesmedco.API, nbHosts)
	for i := 0; i < nbHosts; i++ {
		clients[i] = servicesmedco.NewMedCoClient(el.List[i%len(el.List)], strconv.Itoa(i))
	}

	return clients
}

func getQueryParams(nbQp int, encKey kyber.Point) libunlynx.CipherVector {
	listQueryParameters := make(libunlynx.CipherVector, 0)

	for i := 0; i < nbQp; i++ {
		listQueryParameters = append(listQueryParameters, *libunlynx.EncryptInt(encKey, int64(i)))
	}

	return listQueryParameters
}

func TestServiceDDT(t *testing.T) {
	// test with 10 servers
	el, local := getParam(10)
	// test with 10 concurrent clients
	clients := getClients(10, el)
	// the first two threads execute the same operation (repetition) to check that in the end it yields the same result
	clients[1] = clients[0]
	// test the query DDT with 500 query terms
	nbQp := 100
	qt := getQueryParams(nbQp, el.Aggregate)
	defer local.CloseAll()

	proofs := false

	results := make(map[string][]libunlynx.GroupingKey)

	wg := libunlynx.StartParallelize(len(clients))
	var mutex = sync.Mutex{}
	for i, client := range clients {
		go func(i int, client *servicesmedco.API) {
			defer wg.Done()

			_, res, tr, err := client.SendSurveyDDTRequestTerms(el, servicesmedco.SurveyID("testDDTSurvey_"+client.ClientID), qt, proofs, true)
			mutex.Lock()
			results["testDDTSurvey_"+client.ClientID] = res
			mutex.Unlock()

			if err != nil {
				t.Fatal("Client", client.ClientID, " service did not start: ", err)
			}
			log.Lvl1("Time:", tr.MapTR)
		}(i, client)
	}
	libunlynx.EndParallelize(wg)

	for _, result := range results {
		assert.Equal(t, len(qt), len(result))
	}
	assert.Equal(t, results["testDDTSurvey_"+clients[0].ClientID], results["testDDTSurvey_"+clients[1].ClientID])
}

func TestServiceKS(t *testing.T) {
	// test with 10 servers
	el, local := getParam(10)
	// test with 10 concurrent clients
	nbHosts := 10
	clients := getClients(nbHosts, el)
	defer local.CloseAll()

	proofs := false

	secKeys := make([]kyber.Scalar, 0)
	pubKeys := make([]kyber.Point, 0)
	targetData := make(libunlynx.CipherVector, 0)
	results := make([][]int64, nbHosts)

	for i := 0; i < nbHosts; i++ {
		_, sK, pK := libunlynx.GenKeys(1)
		secKeys = append(secKeys, sK[0])
		pubKeys = append(pubKeys, pK[0])

		targetData = append(targetData, *libunlynx.EncryptInt(el.Aggregate, int64(i)))
	}

	wg := libunlynx.StartParallelize(nbHosts)
	var mutex = sync.Mutex{}
	for i, client := range clients {
		go func(i int, client *servicesmedco.API) {
			defer wg.Done()

			_, res, tr, err := client.SendSurveyKSRequest(el, servicesmedco.SurveyID("testKSRequest_"+client.ClientID), pubKeys[i], targetData, proofs)
			if err != nil {
				t.Fatal("Client", client.ClientID, " service did not start: ", err)
			}

			decRes := make([]int64, 0)
			for _, val := range res {
				decRes = append(decRes, libunlynx.DecryptInt(secKeys[i], val))
			}
			mutex.Lock()
			results[i] = decRes
			mutex.Unlock()
			log.Lvl1("Time:", tr.MapTR)
		}(i, client)
	}
	libunlynx.EndParallelize(wg)

	// Check result
	for _, res := range results {
		for i := 0; i < nbHosts; i++ {
			assert.Equal(t, res[i], int64(i))
		}
	}
}

func TestServiceAgg(t *testing.T) {
	// test with 10 servers
	el, local := getParam(10)
	// test with 10 concurrent clients
	nbHosts := 10
	clients := getClients(nbHosts, el)
	defer local.CloseAll()

	proofs := false

	secKeys := make([]kyber.Scalar, 0)
	pubKeys := make([]kyber.Point, 0)
	targetData := *libunlynx.EncryptInt(el.Aggregate, int64(1))
	results := make([]int64, nbHosts)

	for i := 0; i < nbHosts; i++ {
		_, sK, pK := libunlynx.GenKeys(1)
		secKeys = append(secKeys, sK[0])
		pubKeys = append(pubKeys, pK[0])
	}

	wg := libunlynx.StartParallelize(nbHosts)
	var mutex = sync.Mutex{}
	for i, client := range clients {
		go func(i int, client *servicesmedco.API) {
			defer wg.Done()

			_, res, tr, err := client.SendSurveyAggRequest(el, servicesmedco.SurveyID("testAggRequest"), pubKeys[i], targetData, proofs)
			if err != nil {
				t.Fatal("Client", client.ClientID, " service did not start: ", err)
			}

			mutex.Lock()
			results[i] = libunlynx.DecryptInt(secKeys[i], res)
			mutex.Unlock()
			log.Lvl1("Time:", tr.MapTR)
		}(i, client)
	}
	libunlynx.EndParallelize(wg)

	// Check result
	for _, res := range results {
		assert.Equal(t, res, int64(10))
	}
}

func TestServiceShuffle(t *testing.T) {
	// test with 10 servers
	el, local := getParam(10)
	// test with 10 concurrent clients
	nbHosts := 10
	clients := getClients(nbHosts, el)
	defer local.CloseAll()

	proofs := false

	secKeys := make([]kyber.Scalar, 0)
	pubKeys := make([]kyber.Point, 0)
	targetData := make(libunlynx.CipherVector, 0)
	results := make([]int64, nbHosts)

	for i := 0; i < nbHosts; i++ {
		_, sK, pK := libunlynx.GenKeys(1)
		secKeys = append(secKeys, sK[0])
		pubKeys = append(pubKeys, pK[0])

		targetData = append(targetData, *libunlynx.EncryptInt(el.Aggregate, int64(i)))
	}

	wg := libunlynx.StartParallelize(nbHosts)
	var mutex = sync.Mutex{}
	for i, client := range clients {
		go func(i int, client *servicesmedco.API) {
			defer wg.Done()

			_, res, tr, err := client.SendSurveyShuffleRequest(el, servicesmedco.SurveyID("testShuffleRequest"), pubKeys[i], targetData[i], proofs)
			if err != nil {
				t.Fatal("Client", client.ClientID, " service did not start: ", err)
			}

			mutex.Lock()
			results[i] = libunlynx.DecryptInt(secKeys[i], res)
			mutex.Unlock()
			log.Lvl1("Time:", tr.MapTR)
		}(i, client)
	}
	libunlynx.EndParallelize(wg)

	// Check result
	for i := 0; i < nbHosts; i++ {
		assert.Contains(t, results, int64(i))
	}
}

func TestCheckDDTSecrets(t *testing.T) {
	addr := network.NewLocalAddress("local://127.0.0.1:2020")
	_, err := servicesmedco.CheckDDTSecrets("secrets.toml", addr)
	assert.Nil(t, err, "Error while writing the secrets to the TOML file")

	addr = network.NewLocalAddress("local://127.0.0.1:2010")
	_, err = servicesmedco.CheckDDTSecrets("secrets.toml", addr)
	assert.Nil(t, err, "Error while writing the secrets to the TOML file")

	addr = network.NewLocalAddress("local://127.0.0.1:2000")
	_, err = servicesmedco.CheckDDTSecrets("secrets.toml", addr)
	assert.Nil(t, err, "Error while writing the secrets to the TOML file")
}

func TestReplicateNodes(t *testing.T) {
	nbHosts := 3
	nodesToAdd := 3
	el, _ := getParam(nbHosts)

	sks := make([]kyber.Scalar, 0)
	pubKs := make([]kyber.Point, 0)
	ephemeral := make([][]kyber.Scalar, 0)
	for _, cl := range el.List {
		sks = append(sks, cl.GetPrivate().Clone())
		pubKs = append(pubKs, cl.Public.Clone())
		ephemeral = append(ephemeral, libunlynx.RandomScalarSlice(nbHosts))
	}

	expectedSums := addEphemeralCollumnWise(ephemeral)

	newSks, newPubks, newEphemeral := servicesmedco.ReplicateNodes(sks, ephemeral, nodesToAdd)
	assert.Equal(t, len(newSks), nodesToAdd+nbHosts)
	assert.Equal(t, len(newSks), len(newPubks))
	assert.Equal(t, len(newSks), len(newEphemeral))

	// check pubKeys
	aggregate := newPubks[0]
	for i:=1; i<len(newPubks); i++ {
		aggregate = aggregate.Add(aggregate, newPubks[i])
	}
	assert.Equal(t, el.Aggregate.String(), aggregate.String())

	// check privKeys
	aggregate = libunlynx.SuiTe.Point().Mul(newSks[0], nil)
	for i:=1; i<len(newPubks); i++ {
		aggregate = aggregate.Add(aggregate, libunlynx.SuiTe.Point().Mul(newSks[i], nil))
	}
	assert.Equal(t, el.Aggregate.String(), aggregate.String())

	//check ephemeral
	realSums := addEphemeralCollumnWise(newEphemeral)
	for i, expected := range expectedSums {
		assert.Equal(t, expected.String(), realSums[i].String())
	}
}

func addEphemeralCollumnWise(data [][]kyber.Scalar) []kyber.Scalar {
	expectedSums := make([]kyber.Scalar, len(data[0]))
	copy(expectedSums, data[0])
	for i:=1; i<len(data); i++ {
		for j := 0; j < len(data[i]); j++ {
			tmp := expectedSums[j].Clone()
			tmp = tmp.Add(tmp, data[i][j])
			expectedSums[j] = tmp.Clone()
		}
	}
	return expectedSums
}


func TestA(t *testing.T) {
	sksBase64 := []string{"af457bd25e2401e20f92ef1f1564a4716e3a1b10be3ab3c5f9cd0a1c81f34f07", "4203b0fb2dbe5ccb8cff358d5be42fd8612e5269b5d6ad0d22c613371641fe04", "8d1b40debecfb8324cbe303129ef7e9ebd66b5ce660adeed7bbdabc753837908"}
	pubksBase64 := []string{"2fb70ecd3347316b2c1fa130b3ef18be60daa4d3d3cc66a8bbb409c57a1d66c8", "b46f755195b594c6fd056036f276b00197da04801c01f32fb055f6abf606a2b1", "071e379405706e0cab11c4ad2509180f36859b8cfdc88c3cf68882fe266571ea"}
	ephemeralBase64 := [][]string{{"mmTfA84oZHkURF0wBeu3nQRJT6sjvkFhCSwE/TbAmwo=", "fSyKyMkTfyYEc01uDFLHaEqlaaQUdOb8sV3sNfqyFwI=", "Pz2h3j50HEMNq2txvRZgsf+r48j57ONeMdm1MqLSfgc="},
		{"87hq8MgGbKy9Oa0XNezfQ7B69Ky6IdiutkTZACRC5As=", "70hhKYYfwYugN7fCobPWHApxQIRzpmk/vOtO5CftDwE=", "LZ74i54VwEUZXkJGqb0YQoGMfXm/XAbjHoT0phvNnAs="},
	{"EXmTRaSldsQviB+o9OyG9PSJPFgMzrNxHqkFmL8GCgU=", "pMfvHlZ4M9t5RXF9n0/aPN/qMoSQxVghYovy5ihhcQ4=", "BiDdI1Xg1MgGmDDXP/MXhqaQPVUDGIb54yfBLzsuhQc="}}

	sks := make([]kyber.Scalar, 0)
	pubks := make([]kyber.Point, 0)
	ephemeral := make([][]kyber.Scalar, 0)
	for i:=0; i<3; i++ {
		tmpSk, err := encoding.StringHexToScalar(libunlynx.SuiTe, sksBase64[i])
		assert.NoError(t, err)
		sks = append(sks, tmpSk)

		tmpPk, err := encoding.StringHexToPoint(libunlynx.SuiTe, pubksBase64[i])
		assert.NoError(t, err)
		pubks = append(pubks, tmpPk)

		tmpEp := make([]kyber.Scalar, 0)
		for j:=0; j<3; j++ {
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

	newSks, newPubks, newEphemeral := servicesmedco.ReplicateNodes(sks, ephemeral, 3)

	for i:=0; i<len(newSks); i++{
		log.LLvl1("Node", i, ":")

		strSk, err := encoding.ScalarToStringHex(libunlynx.SuiTe, newSks[i])
		assert.NoError(t, err)
		log.LLvl1("Secret Key [", i, "]:", strSk)

		strPk, err := encoding.PointToStringHex(libunlynx.SuiTe, newPubks[i])
		assert.NoError(t, err)
		log.LLvl1("Public Key [", i, "]:", strPk)

		log.LLvl1("Ephemeral [", i, "]:")
		for j:=0; j<len(newEphemeral[i]); j++ {
			strEp, err := libunlynx.SerializeScalar(newEphemeral[i][j])
			assert.NoError(t, err)
			log.LLvl1(strEp)
		}
		log.LLvl1("")
	}


	// check pubKeys
	aggregateExpected := pubks[0]
	for i:=1; i<len(pubks); i++ {
		aggregateExpected = aggregateExpected.Add(aggregateExpected, pubks[i])
	}
	aggregate := newPubks[0]
	for i:=1; i<len(newPubks); i++ {
		aggregate = aggregate.Add(aggregate, newPubks[i])
	}
	assert.Equal(t, aggregateExpected.String(), aggregate.String())

	// check pubKeys
	aggregateExpected = libunlynx.SuiTe.Point().Mul(sks[0], nil)
	for i:=1; i<len(sks); i++ {
		aggregateExpected = aggregateExpected.Add(aggregateExpected, libunlynx.SuiTe.Point().Mul(sks[i], nil))
	}
	aggregate = libunlynx.SuiTe.Point().Mul(newSks[0], nil)
	for i:=1; i<len(newSks); i++ {
		aggregate = aggregate.Add(aggregate, libunlynx.SuiTe.Point().Mul(newSks[i], nil))
	}
	assert.Equal(t, aggregateExpected.String(), aggregate.String())

	// check ephemeral
	realSums := addEphemeralCollumnWise(newEphemeral)
	for i:=0; i<len(realSums); i++ {
		if i < len(expectedSums) {
			assert.Equal(t, expectedSums[i].String(), realSums[i].String())
		} else {
			assert.Equal(t, expectedSums[0].String(), realSums[i].String())
		}

	}

}

