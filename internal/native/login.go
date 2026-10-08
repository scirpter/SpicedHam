package native

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"snapnative/internal/account"
)

const (
	LoginHost       = "aws.api.snapchat.com"
	LoginMethod     = "/snapchat.janus.api.LoginService/LoginWithPassword"
	APIGatewayScope = "https://auth.snapchat.com/snap_token/api/api-gateway"
)

// DefaultFideliusVersion is Tk8.a's version for this APK's false-by-default
// FIDELIUS_GENERATE_V9_KEY flag (Ei8.t0); a real resolved true flag produces 9.
const DefaultFideliusVersion int64 = 10

type PasswordInput struct {
	Credentials  account.Credentials
	Installation account.Installation
	// Fresh tentative material owned by this submission, not an installation.
	// The transport generates it before executing native password attestation.
	Fidelius account.FideliusKeys
	Context  PasswordContext
	// AndroidIdentifier is canonical raw eight-byte SSAID, without the Ci8 tag.
	AndroidIdentifier []byte
	// Zero selects the APK default; 9 requires its actually resolved config flag.
	FideliusVersion    int64
	Attestation        []byte
	ArgosConfiguration []byte
	CofRoutingTag      string
	CofETag            string
	CofBitmap          []byte
	SequenceIDs        []int32
	CloudAccountID     string
	DeviceTokenID      string
	// Each element is serialized original P8m from the genuinely requested
	// provider, not a raw vendor token or a passing fixture.
	ClientIntegrityResults [][]byte
	// Only the selected account's own previous keys may satisfy an existing
	// server Fidelius binding. They are never an authentication substitute.
	PreviousSession *account.NativeSession
}

// PasswordContext is y4c/sWe submission state, not a server-issued session.
// Direct nonce challenges retain it and the tentative keys, changing only the
// request ID. A COS login-stage initialization instead generates fresh keys.
type PasswordContext struct {
	FlowID                  string
	AuthenticationSessionID string
	AttemptID               string // Genuinely nullable in the original builder.
	NetworkRequestID        string
	NumAttempts             int32
}

func NewPasswordContext() (PasswordContext, error) {
	var context PasswordContext
	var err error
	for _, field := range []*string{&context.FlowID, &context.AuthenticationSessionID, &context.NetworkRequestID} {
		*field, err = account.FreshUUID()
		if err != nil {
			return PasswordContext{}, err
		}
	}
	context.NumAttempts = 1
	return context, nil
}

// BuildPasswordLogin serializes the current APK's first manual submission.
// Attestation must be the actual encrypted vkt.h.f result for passwordLogin;
// the protobuf input to that function is not an authentication proof.
func BuildPasswordLogin(input PasswordInput) ([]byte, error) {
	if input.Credentials.Username == "" || input.Credentials.Password == "" {
		return nil, errors.New("native password login requires username and password")
	}
	if len(input.Attestation) == 0 {
		return nil, errors.New("native password login requires a freshly generated encrypted passwordLogin attestation")
	}
	if input.Installation.ClientID == "" || input.Installation.InstanceUUID == "" {
		return nil, errors.New("native login requires this account's persisted installation")
	}
	if input.CloudAccountID == "" {
		return nil, errors.New("native login requires this account's persisted cloud account ID")
	}
	var priorIWEK []byte
	if input.PreviousSession != nil {
		if !strings.EqualFold(input.PreviousSession.Username, input.Credentials.Username) {
			return nil, errors.New("prior Fidelius material belongs to a different selected account")
		}
		priorIWEK = input.PreviousSession.Fidelius.IWEK
	}
	fidelius, err := buildFidelius(input.Fidelius, input.AndroidIdentifier, input.FideliusVersion, priorIWEK)
	if err != nil {
		return nil, err
	}
	if input.Context.FlowID == "" || input.Context.AuthenticationSessionID == "" || input.Context.NetworkRequestID == "" || input.Context.NumAttempts <= 0 {
		return nil, errors.New("native password request requires its owned flow, authentication, request and submission context")
	}
	header := make([]byte, 0, len(input.Attestation)+300)
	header = stringField(header, 1, input.Installation.ClientID)
	header = stringField(header, 2, input.Context.FlowID)
	header = stringField(header, 3, input.Context.AuthenticationSessionID)
	if input.Context.AttemptID != "" {
		header = stringField(header, 4, input.Context.AttemptID)
	}
	header = stringField(header, 5, input.Context.NetworkRequestID)
	header = stringField(header, 6, input.Installation.InstanceUUID)
	sequences := make([]byte, 0, len(input.SequenceIDs)*3)
	for _, sequence := range input.SequenceIDs {
		sequences = varintField(sequences, 1, uint64(int64(sequence)))
	}
	header = bytesField(header, 7, sequences) // present even when empty
	header = stringField(header, 8, input.CloudAccountID)
	if input.DeviceTokenID != "" {
		device := stringField(nil, 1, input.DeviceTokenID)
		header = bytesField(header, 10, device)
	}
	header = bytesField(header, 11, input.Attestation)
	for _, result := range input.ClientIntegrityResults {
		header = bytesField(header, 14, result)
	}

	configuration := make([]byte, 0, len(input.CofRoutingTag)+len(input.CofETag)+len(input.CofBitmap)+16)
	configuration = stringField(configuration, 1, input.CofRoutingTag)
	configuration = stringField(configuration, 2, input.CofETag)
	configuration = varintField(configuration, 3, 382)
	configuration = bytesField(configuration, 4, input.CofBitmap)

	request := make([]byte, 0, len(header)+len(fidelius)+len(configuration)+len(input.Credentials.Username)+len(input.Credentials.Password)+32)
	identifierField := protowire.Number(1)
	if strings.Contains(input.Credentials.Username, "@") {
		identifierField = 2
	} else if isPhoneIdentifier(input.Credentials.Username) {
		identifierField = 3
	}
	request = stringField(request, identifierField, input.Credentials.Username)
	request = stringField(request, 4, input.Credentials.Password)
	request = varintField(request, 5, uint64(input.Context.NumAttempts))
	request = bytesField(request, 7, fidelius)
	request = bytesField(request, 8, configuration)
	request = varintField(request, 9, 1)
	request = varintField(request, 11, 0)
	request = bytesField(request, 15, header)
	return request, nil
}

func isPhoneIdentifier(identifier string) bool {
	if len(identifier) < 2 || identifier[0] != '+' {
		return false
	}
	for index := 1; index < len(identifier); index++ {
		if identifier[index] < '0' || identifier[index] > '9' {
			return false
		}
	}
	return true
}

func buildFidelius(keys account.FideliusKeys, androidIdentifier []byte, version int64, priorIWEK []byte) ([]byte, error) {
	if version == 0 {
		version = DefaultFideliusVersion
	}
	if len(keys.IWEK) != 32 || len(androidIdentifier) != 8 || (version != 9 && version != DefaultFideliusVersion) {
		return nil, errors.New("Fidelius requires genuine pending keys, canonical raw eight-byte SSAID and APK key version 9 or 10")
	}
	publicKey, err := x509.ParsePKIXPublicKey(keys.PublicKeySPKI)
	if err != nil {
		return nil, fmt.Errorf("parse pending Fidelius public key: %w", err)
	}
	ec, valid := publicKey.(*ecdsa.PublicKey)
	if !valid || ec.Curve != elliptic.P256() || len(keys.PublicKeySPKI) != 91 {
		return nil, errors.New("Fidelius public key must be a P-256 SPKI")
	}
	mac := hmac.New(sha256.New, keys.IWEK)
	_, _ = mac.Write(keys.PublicKeySPKI)
	proof := mac.Sum(nil)
	key := make([]byte, 0, 140)
	key = bytesField(key, 1, keys.PublicKeySPKI[len(keys.PublicKeySPKI)-65:])
	key = bytesField(key, 2, proof)
	key = bytesField(key, 3, keys.IWEK)
	key = varintField(key, 4, uint64(version))
	capacity := len(key) + 16
	if len(priorIWEK) != 0 {
		capacity += 1 + protowire.SizeBytes(len(priorIWEK))
	}
	init := make([]byte, 0, capacity)
	if len(priorIWEK) != 0 {
		init = bytesField(init, 1, priorIWEK)
	}
	init = bytesField(init, 2, key)
	// Ui8.e -> zc2(case 4) -> m7e.g prefixes the decoded SSAID with type 7.
	var taggedIdentifier [9]byte
	taggedIdentifier[0] = 0x07
	copy(taggedIdentifier[1:], androidIdentifier)
	init = bytesField(init, 3, taggedIdentifier[:])
	return init, nil
}

type LoginError struct {
	Status uint64
	Branch protowire.Number
	// Message is LH7.field1: the original client exposes it as the user-facing
	// rejection reason. It is not a challenge token or authenticated session.
	Message string
	// Opaque response-bound challenge state is owned here, never logged.
	// A challenge is not authentication; missing real providers fail closed.
	Challenge          []byte
	AuthSessionPayload []byte
}

func (e *LoginError) Error() string {
	description := fmt.Sprintf("native password login was not authenticated: application status=%d, response branch=%d", e.Status, e.Branch)
	if e.Message != "" {
		description += fmt.Sprintf(", server message=%q", e.Message)
	}
	switch e.Status {
	case 7:
		description += "; genuine requested SafetyNet result is unavailable (deprecated by this APK)"
	case 9:
		description += "; genuine nonce-bound Google Play Integrity Classic result required"
	case 17:
		description += "; genuine nonce-bound Google Play Integrity Standard result required"
	case 18:
		description += "; genuine AndroidKeyStore challenge-bound attestation certificate chain required"
	case 21:
		description += "; original COS login-stage challenge completion required"
	}
	return description
}

// ParsePasswordSession requires the success branch, its real account identity,
// and a successful server-issued token bundle. HTTP status is not consulted.
func ParsePasswordSession(payload []byte, now time.Time) (*account.NativeSession, error) {
	response, err := parsePasswordResponse(payload)
	if err != nil {
		return nil, err
	}
	return response.session(now)
}

type passwordResponse struct {
	status             uint64
	branch             protowire.Number
	body               []byte
	authSessionPayload []byte
}

func parsePasswordResponse(payload []byte) (passwordResponse, error) {
	d := decoder{rest: payload}
	var response passwordResponse
	var active []byte
	for {
		// Start at the last oneof switch. Same-branch messages within this
		// tail merge; a switch never inherits earlier identity/token state.
		tail := d.rest
		entry, ok := d.next()
		if !ok {
			break
		}
		var err error
		switch {
		case entry.number == 1:
			response.status, err = entry.asVarint()
		case entry.number >= 2 && entry.number <= 13:
			if response.branch != entry.number {
				active = tail
			}
			response.branch = entry.number
			_, err = entry.asBytes()
		case entry.number == 14:
			response.authSessionPayload, err = entry.asBytes()
		}
		if err != nil {
			return passwordResponse{}, err
		}
	}
	if d.err != nil {
		return passwordResponse{}, d.err
	}
	if response.branch != 0 {
		var err error
		response.body, _, err = messageField(active, response.branch)
		if err != nil {
			return passwordResponse{}, err
		}
	}
	return response, nil
}

func (response passwordResponse) session(now time.Time) (*account.NativeSession, error) {
	if response.status != 1 || response.branch != 2 {
		rejection := &LoginError{Status: response.status, Branch: response.branch}
		switch response.status {
		case 7, 9, 17, 18, 21:
			rejection.Challenge = bytes.Clone(response.body)
			rejection.AuthSessionPayload = bytes.Clone(response.authSessionPayload)
		}
		if response.branch == 11 {
			failure := decoder{rest: response.body}
			for entry, ok := failure.next(); ok; entry, ok = failure.next() {
				if entry.number == 1 {
					message, err := entry.asBytes()
					if err != nil {
						return nil, err
					}
					rejection.Message = string(message)
				}
			}
			if failure.err != nil {
				return nil, failure.err
			}
		}
		return nil, rejection
	}
	identity, present, err := messageField(response.body, 1)
	if err != nil || !present {
		return nil, errors.New("native login success has no authenticated account identity")
	}
	session := &account.NativeSession{}
	bundle, _, err := messageField(identity, 6)
	if err != nil {
		return nil, err
	}
	d := decoder{rest: identity}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number != 1 && entry.number != 2 {
			continue
		}
		value, err := entry.asBytes()
		if err != nil {
			return nil, err
		}
		switch entry.number {
		case 1:
			session.UserID = string(value)
		case 2:
			session.Username = string(value)
		}
	}
	if d.err != nil {
		return nil, d.err
	}
	if session.UserID == "" || session.Username == "" || bundle == nil {
		return nil, errors.New("native login lacks issued account identity or token bundle")
	}
	if err := parseTokenBundle(bundle, session, now.Unix()); err != nil {
		return nil, err
	}
	session.DeviceToken, err = parseDeviceToken(response.body)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func parseDeviceToken(success []byte) (*account.DeviceToken, error) {
	initialization, _, err := messageField(success, 7)
	if err != nil {
		return nil, err
	}
	payload, present, err := messageField(initialization, 1)
	if err != nil || !present {
		return nil, err
	}
	token := &account.DeviceToken{}
	d := decoder{rest: payload}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number != 1 && entry.number != 2 {
			continue
		}
		value, err := entry.asBytes()
		if err != nil {
			return nil, err
		}
		if entry.number == 1 {
			token.ID = string(value)
		} else {
			token.Value = string(value)
		}
	}
	return token, d.err
}

func parseTokenBundle(payload []byte, session *account.NativeSession, now int64) error {
	timing, _, err := messageField(payload, 4)
	if err != nil {
		return err
	}
	offsetA, offsetB, err := parseTokenOffsets(timing)
	if err != nil {
		return err
	}
	d := decoder{rest: payload}
	var status uint64
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		var err error
		switch entry.number {
		case 1:
			var raw []byte
			raw, err = entry.asBytes()
			session.RefreshToken = string(raw)
		case 2:
			var raw []byte
			raw, err = entry.asBytes()
			if err == nil {
				var token account.AccessToken
				token, err = parseAccessToken(raw)
				if err == nil {
					session.Tokens = append(session.Tokens, token)
				}
			}
		case 3:
			status, err = entry.asVarint()
		}
		if err != nil {
			return err
		}
	}
	if d.err != nil {
		return d.err
	}
	if status != 1 || session.RefreshToken == "" {
		return errors.New("native token service did not issue a successful refresh session")
	}
	for index := range session.Tokens {
		token := &session.Tokens[index]
		lifetime := token.ExpiresAt // temporarily holds the network's relative lifetime
		if token.Token == "" || token.Scope == "" || lifetime > math.MaxInt64-now || offsetA > lifetime {
			return errors.New("native token bundle contains an invalid access entry")
		}
		token.RetrievedAt = now
		token.ExpiresAt = now + lifetime - offsetA
		if offsetB >= lifetime {
			token.PrefetchAt = now + (lifetime-offsetA)/5*4 + (lifetime-offsetA)%5*4/5
		} else {
			token.PrefetchAt = now + lifetime - offsetB
		}
	}
	return nil
}

func parseAccessToken(payload []byte) (account.AccessToken, error) {
	d := decoder{rest: payload}
	var token account.AccessToken
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number == 1 || entry.number == 2 {
			value, err := entry.asBytes()
			if err != nil {
				return token, err
			}
			if entry.number == 1 {
				token.Token = string(value)
			} else {
				token.Scope = string(value)
			}
		} else if entry.number == 3 {
			value, err := entry.asVarint()
			if err != nil || value > math.MaxInt64 {
				return token, errors.New("invalid relative native token lifetime")
			}
			token.ExpiresAt = int64(value)
		}
	}
	return token, d.err
}

func parseTokenOffsets(payload []byte) (int64, int64, error) {
	d := decoder{rest: payload}
	var first, second int64
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number != 1 && entry.number != 2 {
			continue
		}
		value, err := entry.asVarint()
		if err != nil || value > math.MaxInt64 {
			return 0, 0, errors.New("invalid native token timing metadata")
		}
		if entry.number == 1 {
			first = int64(value)
		} else {
			second = int64(value)
		}
	}
	return first, second, d.err
}

func AccessTokenFor(session *account.NativeSession, scope string, now time.Time) (string, error) {
	if session == nil || session.UserID == "" || session.RefreshToken == "" {
		return "", errors.New("no authenticated native account session")
	}
	for _, token := range session.Tokens {
		if token.Scope == scope && token.Token != "" && token.RetrievedAt <= now.Unix() && token.ExpiresAt >= now.Unix() {
			return token.Token, nil
		}
	}
	return "", fmt.Errorf("native account has no valid access token for scope %s", scope)
}
