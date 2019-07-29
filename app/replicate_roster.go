package main

import (
	"encoding/base64"
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/encoding"
	"go.dedis.ch/onet/v3/log"
	"gopkg.in/urfave/cli.v1"
	"os"
)

type node struct {
	PubKey  string
	SecKey  string
	Secrets []string
}
type nodes struct {
	Node []node
}

// replicateRoster gets a collection of privates keys and ephemeral secrets and generates X new keys and secrets for Y
// new servers while keeping the collective key and the result of a DDT the same
func replicateRoster(c *cli.Context) error {
	var err error

	keysTomlFile := c.String("keysTomlFile")
	nodesToAdd := c.Int("nodesToAdd")
	if nodesToAdd <= 0 {
		return errors.New("need to specify one or more nodes to add: >0")
	}
	outputTomlFile := c.String("outputTomlFile")

	var roster nodes
	if _, err := toml.DecodeFile(keysTomlFile, &roster); err != nil {
		return err
	}

	// convert strings to scalars and points
	sks := make([]kyber.Scalar, 0)
	pubks := make([]kyber.Point, 0)
	ephemeral := make([][]kyber.Scalar, 0)
	for i := 0; i < len(roster.Node); i++ {
		var tmpSk kyber.Scalar
		if tmpSk, err = encoding.StringHexToScalar(libunlynx.SuiTe, roster.Node[i].SecKey); err != nil {
			return err
		}
		sks = append(sks, tmpSk)

		var tmpPk kyber.Point
		if tmpPk, err = encoding.StringHexToPoint(libunlynx.SuiTe, roster.Node[i].PubKey); err != nil {
			return err
		}
		pubks = append(pubks, tmpPk)

		tmpEp := make([]kyber.Scalar, 0)
		for j := 0; j < len(roster.Node); j++ {
			secret := libunlynx.SuiTe.Scalar()
			var b []byte
			if b, err = base64.StdEncoding.DecodeString(roster.Node[i].Secrets[j]); err != nil {
				return err
			}

			if err = secret.UnmarshalBinary(b); err != nil {
				return err
			}
			tmpEp = append(tmpEp, secret)
		}
		ephemeral = append(ephemeral, tmpEp)
	}

	// replicate keys and secrets
	newSks, newPubks, newEphemeral := replicateNodes(sks, ephemeral, nodesToAdd)

	// convert scalars and points back to string
	var outputRoster nodes
	outputRoster.Node = make([]node, len(newSks))
	for i := 0; i < len(newSks); i++ {
		var strSk, strPk, strEp string
		strEpList := make([]string, len(newEphemeral[i]))

		if strSk, err = encoding.ScalarToStringHex(libunlynx.SuiTe, newSks[i]); err != nil {
			return err
		}
		if strPk, err = encoding.PointToStringHex(libunlynx.SuiTe, newPubks[i]); err != nil {
			return err
		}
		for j := 0; j < len(newEphemeral[i]); j++ {
			if strEp, err = libunlynx.SerializeScalar(newEphemeral[i][j]); err != nil {
				return err
			}
			strEpList[j] = strEp
		}

		node := node{
			PubKey:  strPk,
			SecKey:  strSk,
			Secrets: strEpList,
		}
		outputRoster.Node[i] = node
	}

	// generate output file
	fileHandle, err := os.Create(outputTomlFile)
	defer fileHandle.Close()
	if err != nil {
		log.Error(err)
		return err
	}

	encoder := toml.NewEncoder(fileHandle)
	err = encoder.Encode(&outputRoster)
	if err != nil {
		log.Error(err)
		return err
	}

	return nil
}

func splitNodeSecrets(rootSk kyber.Scalar, rootEphemeral []kyber.Scalar, nbrSplits int) ([]kyber.Scalar, []kyber.Point, [][]kyber.Scalar) {
	sks := libunlynx.SplitScalar(rootSk.Clone(), nbrSplits)
	pubks := make([]kyber.Point, nbrSplits+1)
	ephemeral := make([][]kyber.Scalar, nbrSplits+1)

	// generate new PubKeys
	for i := 0; i < nbrSplits+1; i++ {
		pubks[i] = libunlynx.SuiTe.Point().Mul(sks[i], nil)
		ephemeral[i] = make([]kyber.Scalar, 0)
	}

	// split rootEphemeral key
	for _, ep := range rootEphemeral {
		newEps := libunlynx.SplitScalar(ep.Clone(), nbrSplits)
		for i, newEp := range newEps {
			ephemeral[i] = append(ephemeral[i], newEp)
		}
	}
	return sks, pubks, ephemeral

}

func replicateNodes(sks []kyber.Scalar, ephemeral [][]kyber.Scalar, nodesToAdd int) ([]kyber.Scalar, []kyber.Point, [][]kyber.Scalar) {
	pubks := make([]kyber.Point, 0)
	for i := 0; i < len(sks); i++ {
		pubks = append(pubks, libunlynx.SuiTe.Point().Mul(sks[i], nil))
	}

	for i := 0; i < len(ephemeral); i++ {
		for j := 0; j < nodesToAdd; j++ {
			ephemeral[i] = append(ephemeral[i], ephemeral[i][0])
		}
	}

	newSks, newPubks, newEphemeral := splitNodeSecrets(sks[0], ephemeral[0], nodesToAdd)

	// remove the root of the replication
	sks = sks[1:]
	pubks = pubks[1:]
	ephemeral = ephemeral[1:]

	// append new data
	sks = append(sks, newSks...)
	pubks = append(pubks, newPubks...)
	ephemeral = append(ephemeral, newEphemeral...)

	return sks, pubks, ephemeral
}
