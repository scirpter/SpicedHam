package native

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"snapnative/internal/account"
)

type NetworkProfile struct {
	UserAgent      string
	AcceptLanguage string
	JanusRouteTag  string
}

type Client struct {
	username string
	profile  NetworkProfile
	login    *grpc.ClientConn
	friends  *grpc.ClientConn
}

type packet []byte

type nativeCodec struct{}

func (nativeCodec) Name() string { return "proto" }

func (nativeCodec) Marshal(value any) ([]byte, error) {
	payload, valid := value.(*packet)
	if !valid {
		return nil, errors.New("native RPC codec requires an actual protobuf packet")
	}
	return *payload, nil
}

func (nativeCodec) Unmarshal(source []byte, value any) error {
	payload, valid := value.(*packet)
	if !valid {
		return errors.New("native RPC codec requires an actual response packet")
	}
	// gRPC owns and releases its incoming buffer after Unmarshal. The packet
	// must retain its own bytes until its session/friend parser has run.
	*payload = append((*payload)[:0], source...)
	return nil
}

// Each selected account owns separate native connections and per-call metadata.
// No global session, browser cookie jar, bearer-token interceptor or WebLogin exists.
func NewClient(username string, profile NetworkProfile) (*Client, error) {
	if username == "" || profile.UserAgent == "" || profile.AcceptLanguage == "" {
		return nil, errors.New("native client requires account identity and actual runtime network profile")
	}
	options := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
		grpc.WithUserAgent(profile.UserAgent),
		grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(nativeCodec{}), grpc.MaxCallRecvMsgSize(math.MaxInt32)),
	}
	login, err := grpc.NewClient(LoginHost+":443", options...)
	if err != nil {
		return nil, err
	}
	friends, err := grpc.NewClient(FriendsHost+":443", options...)
	if err != nil {
		login.Close()
		return nil, err
	}
	return &Client{username: strings.ToLower(username), profile: profile, login: login, friends: friends}, nil
}

func (c *Client) Close() error {
	return errors.Join(c.login.Close(), c.friends.Close())
}

func (c *Client) LoginWithPassword(ctx context.Context, input PasswordInput, native ArgosNative) (PasswordLoginResult, error) {
	if strings.ToLower(input.Credentials.Username) != c.username {
		return PasswordLoginResult{}, errors.New("password login belongs to a different selected account")
	}
	if input.PreviousSession != nil && strings.ToLower(input.PreviousSession.Username) != c.username {
		return PasswordLoginResult{}, errors.New("previous Fidelius identity belongs to a different selected account")
	}
	if native == nil {
		return PasswordLoginResult{}, errors.New("password login requires the actual original native attestation runtime")
	}
	// j4c.o -> uK0.g -> Tk8.a initializes tentative keys BEFORE native f.
	// They are always disposed after this submission; finalized keys have
	// separate ownership authorized by the returned server IWEK/HMAC binding.
	pending, err := account.NewFideliusKeys()
	if err != nil {
		return PasswordLoginResult{}, err
	}
	defer func() {
		clear(pending.IWEK)
		clear(pending.PrivateKeyPKCS8)
		clear(pending.PublicKeySPKI)
	}()
	input.Fidelius = pending
	attestationInput := BuildPasswordAttestationInput(input.ArgosConfiguration)
	proof, err := native.Attest(ctx, attestationInput)
	clear(attestationInput)
	if err != nil {
		return PasswordLoginResult{}, fmt.Errorf("original passwordLogin native f: %w", err)
	}
	defer clear(proof)
	input.Attestation = proof
	encoded, err := BuildPasswordLogin(input)
	if err != nil {
		return PasswordLoginResult{}, err
	}
	defer clear(encoded)
	request := packet(encoded)
	headers := metadata.Pairs(
		"accept-encoding", "br",
		"accept-language", c.profile.AcceptLanguage,
		"x-snap-janus-request-created-at", strconv.FormatInt(time.Now().UnixMilli(), 10),
	)
	if c.profile.JanusRouteTag != "" {
		headers.Set("x-snap-route-tag", c.profile.JanusRouteTag)
	}
	ctx = metadata.NewOutgoingContext(ctx, headers)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var response packet
	// grpc.Invoke establishes grpc-status success before any protobuf is accepted.
	if err := c.login.Invoke(ctx, LoginMethod, &request, &response); err != nil {
		return PasswordLoginResult{}, fmt.Errorf("native LoginWithPassword transport: %w", err)
	}
	defer clear(response)
	decoded, err := parsePasswordResponse(response)
	if err != nil {
		return PasswordLoginResult{}, err
	}
	session, err := decoded.session(time.Now())
	if err != nil {
		return PasswordLoginResult{}, err
	}
	if strings.ToLower(session.Username) != c.username {
		return PasswordLoginResult{}, errors.New("native login issued a session for a different selected account")
	}
	version := input.FideliusVersion
	if version == 0 {
		version = DefaultFideliusVersion
	}
	previous := input.PreviousSession
	if previous != nil && previous.UserID != session.UserID {
		previous = nil // A recycled name cannot authorize another account's keys.
	}
	keys, version, fideliusErr := finalizeFidelius(decoded.body, pending, version, previous)
	session.Fidelius, session.FideliusVersion = keys, version
	return PasswordLoginResult{Session: session, FideliusError: fideliusErr}, nil
}

var errIncompleteArgos = errors.New("Atlas requires a nonempty native Argos token and any required signature")

// Native token types 4/5 legitimately omit att-sign. A present-but-empty
// signature or strict-enforcement-only facade error is not usable Argos output.
func validateRequestAttestation(attestation RequestAttestation) error {
	if attestation.RequestID == "" || attestation.Headers["x-snapchat-att-token"] == "" {
		return errIncompleteArgos
	}
	if signature, present := attestation.Headers["x-snapchat-att-sign"]; present && signature == "" {
		return errIncompleteArgos
	}
	return nil
}

// RequestAttestation retains the native async request context and canonical
// Header map. The server token comes from ArgosService/GetTokens. For signed
// policy types, vkt.h.c signs raw token bytes plus FriendsMethod, not request ID
// or request body. Strict-only/empty-signature facade failures are rejected.
type RequestAttestation struct {
	RequestID string
	Headers   map[string]string
}

func (c *Client) AllFriends(ctx context.Context, session *account.NativeSession, attestation RequestAttestation) (account.FriendSnapshot, error) {
	if session == nil || strings.ToLower(session.Username) != c.username {
		return account.FriendSnapshot{}, errors.New("friend request belongs to a different selected account")
	}
	token, err := AccessTokenFor(session, APIGatewayScope, time.Now())
	if err != nil {
		return account.FriendSnapshot{}, err
	}
	if err := validateRequestAttestation(attestation); err != nil {
		return account.FriendSnapshot{}, err
	}
	headers := metadata.Pairs(
		"x-snap-access-token", token,
		"accept-encoding", "br,gzip",
		"accept-language", c.profile.AcceptLanguage,
		"x-request-id", attestation.RequestID,
	)
	for key, value := range attestation.Headers {
		normalized := strings.ToLower(key)
		if normalized == "x-snap-access-token" || normalized == "authorization" || normalized == "x-request-id" {
			return account.FriendSnapshot{}, errors.New("Argos headers cannot replace selected-account authentication or request identity")
		}
		headers.Set(normalized, value)
	}
	ctx = metadata.NewOutgoingContext(ctx, headers)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request := packet(BuildFullFriendsRequest())
	var response packet
	if err := c.friends.Invoke(ctx, FriendsMethod, &request, &response); err != nil {
		return account.FriendSnapshot{}, fmt.Errorf("native SyncFriendData transport: %w", err)
	}
	return ParseFullFriends(response)
}
