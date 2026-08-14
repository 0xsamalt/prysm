package beacon_api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/helpers"
	"github.com/OffchainLabs/prysm/v7/network/httputil"
	ethpb "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v7/runtime/version"
	"github.com/OffchainLabs/prysm/v7/time/slots"
	"github.com/pkg/errors"
)

// proposeAttestation submits pre-signed attestations of the same fork version in one request.
func (c *beaconApiValidatorClient) proposeAttestation(ctx context.Context, attestations []*ethpb.Attestation) (*ethpb.AttestResponse, error) {
	if len(attestations) == 0 {
		return nil, nil
	}
	for i, att := range attestations {
		if err := helpers.ValidateNilAttestation(att); err != nil {
			return nil, errors.Wrapf(err, "attestation at index %d is invalid", i)
		}
	}
	marshalledAttestations, err := json.Marshal(jsonifyAttestations(attestations))
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal attestations")
	}
	headers := map[string]string{"Eth-Consensus-Version": version.String(attestations[0].Version())}
	if err := c.handler.Post(ctx, "/eth/v2/beacon/pool/attestations", headers, bytes.NewBuffer(marshalledAttestations), nil); err != nil {
		return nil, err
	}
	attestationDataRoot, err := attestations[0].Data.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute attestation data root")
	}
	return &ethpb.AttestResponse{AttestationDataRoot: attestationDataRoot[:]}, nil
}

// proposeAttestationElectra submits pre-signed single attestations of the same slot in one
// request, as an SSZ list of fixed-size items, falling back to JSON on a 415 response.
func (c *beaconApiValidatorClient) proposeAttestationElectra(ctx context.Context, attestations []*ethpb.SingleAttestation) (*ethpb.AttestResponse, error) {
	if len(attestations) == 0 {
		return nil, nil
	}
	for i, att := range attestations {
		if err := helpers.ValidateNilAttestation(att); err != nil {
			return nil, errors.Wrapf(err, "attestation at index %d is invalid", i)
		}
	}
	attestation := attestations[0]
	headers := map[string]string{"Eth-Consensus-Version": version.String(slots.ToForkVersion(attestation.Data.Slot))}

	sszBytes := make([]byte, 0, attestation.SizeSSZ()*len(attestations))
	for _, att := range attestations {
		var err error
		sszBytes, err = att.MarshalSSZTo(sszBytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal attestations to SSZ")
		}
	}
	err := c.handler.PostSSZ(ctx, "/eth/v2/beacon/pool/attestations", headers, bytes.NewBuffer(sszBytes))
	if err != nil {
		errJSON := &httputil.DefaultJsonError{}
		if !errors.As(err, &errJSON) || errJSON.Code != http.StatusUnsupportedMediaType {
			return nil, err
		}
		log.WithError(err).Debug("Beacon node does not accept SSZ attestations, falling back to JSON")

		marshalledAttestations, err := json.Marshal(jsonifySingleAttestations(attestations))
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal attestations")
		}
		if err := c.handler.Post(ctx, "/eth/v2/beacon/pool/attestations", headers, bytes.NewBuffer(marshalledAttestations), nil); err != nil {
			return nil, err
		}
	}
	attestationDataRoot, err := attestation.Data.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute attestation data root")
	}
	return &ethpb.AttestResponse{AttestationDataRoot: attestationDataRoot[:]}, nil
}
