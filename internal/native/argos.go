package native

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"snapnative/internal/account"
)

const (
	ArgosHost   = "gcp.api.snapchat.com"
	ArgosMethod = "/snap.security.ArgosService/GetTokens"
)

// ArgosNative supplies the original scplugin f/c operations from the selected
// account's real native runtime. Inputs are borrowed until return; returned
// bytes belong to the caller. Neither operation creates a server Argos token.
type ArgosNative interface {
	Attest(context.Context, []byte) ([]byte, error)
	Sign(context.Context, []byte, string) ([]byte, error)
}

// The scalar fields remain opaque: their original names and units were not
// recovered. Fresh acquisition needs no guessed lifetime or persistence rules.
type argosTokenAndPolicy struct {
	token     []byte
	scalar2   uint64
	scalar3   uint64
	tokenType uint64
}

type argosTokens struct {
	hot     argosTokenAndPolicy
	cold    argosTokenAndPolicy
	hasCold bool
}

func buildArgosAttestationInput() []byte {
	input := make([]byte, 0, len(ArgosMethod)+8)
	input = stringField(input, 1, "")
	input = stringField(input, 2, ArgosMethod)
	return varintField(input, 3, 0)
}

// FriendsAttestation acquires a fresh server hot token for this selected account
// and signs only policies that require it, using the exact Atlas request path.
// Account sessions retain their existing separate persistence; Argos tokens are
// neither cached globally nor assigned an invented expiry or storage format.
func (c *Client) FriendsAttestation(ctx context.Context, session *account.NativeSession, provider ArgosNative) (RequestAttestation, error) {
	if session == nil || strings.ToLower(session.Username) != c.username {
		return RequestAttestation{}, errors.New("Argos token request belongs to a different selected account")
	}
	accessToken, err := AccessTokenFor(session, APIGatewayScope, time.Now())
	if err != nil {
		return RequestAttestation{}, err
	}
	if provider == nil {
		return RequestAttestation{}, errors.New("Argos requires the selected account's real native f/c provider")
	}
	requestID, err := account.FreshUUID()
	if err != nil {
		return RequestAttestation{}, fmt.Errorf("native Argos request identity: %w", err)
	}
	input := buildArgosAttestationInput()
	defer clear(input)
	payload, err := provider.Attest(ctx, input)
	defer clear(payload)
	if err != nil {
		return RequestAttestation{}, fmt.Errorf("native Argos platform attestation: %w", err)
	}
	if len(payload) == 0 {
		return RequestAttestation{}, errors.New("native Argos platform attestation returned no payload")
	}
	// GetTokensRequest carries actual f output in field 1. Its default-false
	// field 2 and default-zero experiment scalar in field 3 are omitted.
	request := packet(bytesField(make([]byte, 0, len(payload)+16), 1, payload))
	defer clear(request)

	connection := c.friends
	if connection == nil || connection.Target() != ArgosHost+":443" {
		// Atlas normally uses us-east4-gcp, not the recovered Argos gcp host.
		// Keep this exact-host connection scoped to the selected account's call.
		connection, err = grpc.NewClient(ArgosHost+":443",
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
			grpc.WithUserAgent(c.profile.UserAgent),
			grpc.WithDisableRetry(),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(nativeCodec{}), grpc.MaxCallRecvMsgSize(math.MaxInt32)),
		)
		if err != nil {
			return RequestAttestation{}, fmt.Errorf("native Argos connection: %w", err)
		}
		defer connection.Close()
	}
	// Replace, rather than append to, caller metadata: this token RPC requires
	// gateway authentication but must never recursively acquire Argos headers.
	// The source default Argos route tag is empty, independent of JanusRouteTag.
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"x-snap-access-token", accessToken,
		"x-snap-route-tag", "",
	))
	rpcCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var response packet
	defer func() { clear(response) }()
	if err := connection.Invoke(rpcCtx, ArgosMethod, &request, &response); err != nil {
		return RequestAttestation{}, fmt.Errorf("native Argos GetTokens transport: %w", err)
	}
	tokens, err := parseArgosTokens(response)
	if err != nil {
		return RequestAttestation{}, err
	}
	headers := map[string]string{
		"x-snapchat-att-token": base64.URLEncoding.EncodeToString(tokens.hot.token),
	}
	if tokens.hot.tokenType == 2 {
		// c consumes raw server bytes and the request path, not a header, UUID,
		// nk9 input, or friend request body. Native encoding retains '=' padding.
		signature, err := provider.Sign(ctx, tokens.hot.token, FriendsMethod)
		defer clear(signature)
		if err != nil {
			return RequestAttestation{}, fmt.Errorf("native Argos request signature: %w", err)
		}
		if len(signature) == 0 {
			return RequestAttestation{}, errors.New("native Argos request signature returned no bytes")
		}
		headers["x-snapchat-att-sign"] = base64.URLEncoding.EncodeToString(signature)
	}
	return RequestAttestation{RequestID: requestID, Headers: headers}, nil
}

func parseArgosTokens(payload []byte) (argosTokens, error) {
	var tokens argosTokens
	var hasHot bool
	d := decoder{rest: payload}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number != 2 && entry.number != 3 {
			continue
		}
		value, err := entry.asBytes()
		if err != nil {
			return argosTokens{}, fmt.Errorf("native Argos GetTokens field %d: %w", entry.number, err)
		}
		policy := &tokens.hot
		if entry.number == 2 {
			hasHot = true
		} else {
			policy = &tokens.cold
			tokens.hasCold = true
		}
		// Hot and cold are separate slots, not competing oneof branches.
		// Repeated singular messages merge; their bytes/scalars are last-wins.
		if err := parseArgosTokenAndPolicy(value, policy); err != nil {
			return argosTokens{}, fmt.Errorf("native Argos GetTokens field %d: %w", entry.number, err)
		}
	}
	if d.err != nil {
		return argosTokens{}, fmt.Errorf("native Argos GetTokens response: %w", d.err)
	}
	if !hasHot {
		return argosTokens{}, errors.New("native Argos GetTokens response has no hot token")
	}
	if tokens.hot.tokenType != 2 && tokens.hot.tokenType != 4 && tokens.hot.tokenType != 5 {
		return argosTokens{}, fmt.Errorf("native Argos GetTokens response has unusable hot token type %d", tokens.hot.tokenType)
	}
	if len(tokens.hot.token) == 0 {
		return argosTokens{}, errors.New("native Argos GetTokens response has an empty hot token")
	}
	// Native completion accepts an optional cold slot only for types 1/6.
	// An unsupported cold candidate does not replace the mandatory hot token.
	if tokens.hasCold && tokens.cold.tokenType != 1 && tokens.cold.tokenType != 6 {
		tokens.cold = argosTokenAndPolicy{}
		tokens.hasCold = false
	}
	return tokens, nil
}

func parseArgosTokenAndPolicy(payload []byte, policy *argosTokenAndPolicy) error {
	d := decoder{rest: payload}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		var err error
		switch entry.number {
		case 1:
			policy.token, err = entry.asBytes()
		case 2:
			policy.scalar2, err = entry.asVarint()
		case 3:
			policy.scalar3, err = entry.asVarint()
		case 4:
			policy.tokenType, err = entry.asVarint()
		}
		if err != nil {
			return fmt.Errorf("TokenAndPolicy field %d: %w", entry.number, err)
		}
	}
	return d.err
}
