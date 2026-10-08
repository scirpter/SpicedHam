package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"snapnative/internal/account"
)

func testUUID(high, low uint64) []byte {
	value := protowire.AppendFixed64(protowire.AppendTag(nil, 1, protowire.Fixed64Type), high)
	return protowire.AppendFixed64(protowire.AppendTag(value, 2, protowire.Fixed64Type), low)
}

func testRelationship(uuid []byte, username string, kind uint64) []byte {
	value := bytesField(nil, 1, uuid)
	value = stringField(value, 2, username)
	return varintField(value, 4, kind)
}

func testFullResponse(kind uint64, records ...[]byte) []byte {
	metadata := varintField(nil, 2, kind)
	outgoing := bytesField(nil, 1, metadata)
	for _, record := range records {
		outgoing = bytesField(outgoing, 2, record)
	}
	return bytesField(nil, 1, outgoing)
}

func TestFullSnapshotAppliesFinalRelationships(t *testing.T) {
	removed := testUUID(1, 2)
	remaining := testUUID(0x1122334455667788, 0x99aabbccddeeff00)
	unknown := testUUID(3, 4)
	renamed := testRelationship(remaining, "current-name", 2)
	renamed = stringField(renamed, 36, "legacy-name")
	payload := testFullResponse(2,
		testRelationship(removed, "then-blocked", 2),
		testRelationship(remaining, "prior-name", 2),
		testRelationship(removed, "then-blocked", 5),
		testRelationship(unknown, "legacy-enum-zero-is-not-mutual", 0),
		renamed,
		varintField(nil, 4, 6), // A deleted row without UUID is skipped by the native consumer.
	)
	snapshot, err := ParseFullFriends(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Full || len(snapshot.Friends) != 1 {
		t.Fatalf("not the final mutual relationship set: %+v", snapshot)
	}
	friend := snapshot.Friends[0]
	if friend.UserID != "11223344-5566-7788-99aa-bbccddeeff00" || friend.Username != "current-name" || friend.LegacyUsername != "legacy-name" {
		t.Fatalf("incorrect account UUID/current relationship: %+v", friend)
	}
}

func TestCompleteEmptySnapshotIsNotColdDelta(t *testing.T) {
	full, err := ParseFullFriends(testFullResponse(2))
	if err != nil || !full.Full || len(full.Friends) != 0 {
		t.Fatalf("complete empty FULL snapshot rejected: %+v, %v", full, err)
	}
	if delta, err := ParseFullFriends(testFullResponse(1)); err == nil || delta.Full {
		t.Fatalf("cold DELTA was presented as a complete friend list: %+v, %v", delta, err)
	}
}

func TestIncompleteRelationshipCannotPublishFullSnapshot(t *testing.T) {
	valid := testRelationship(testUUID(5, 6), "valid-before-corruption", 2)
	invalid := varintField(nil, 4, 2)
	if snapshot, err := ParseFullFriends(testFullResponse(2, valid, invalid)); err == nil || snapshot.Full {
		t.Fatalf("partial/corrupt friend response was published as complete: %+v, %v", snapshot, err)
	}
}

func TestFideliusSerializesTypedNineByteAndroidIdentifier(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	iwek := make([]byte, 32)
	if _, err := rand.Read(iwek); err != nil {
		t.Fatal(err)
	}
	// Unit wire fixture, not a handset ID: retain leading zero and text order.
	raw := []byte{0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde}
	payload, err := buildFidelius(account.FideliusKeys{IWEK: iwek, PublicKeySPKI: public}, raw, 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	identity, present, err := messageField(payload, 3)
	if err != nil || !present {
		t.Fatalf("Ci8 field 3 missing or not bytes: present=%t, error=%v", present, err)
	}
	expected := []byte{0x07, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde}
	if !bytes.Equal(identity, expected) {
		t.Fatalf("Ci8 field 3 = %x, want typed nine-byte identity %x", identity, expected)
	}
}

func TestPasswordResponseRequiresSuccessOneof(t *testing.T) {
	payload := varintField(nil, 1, 1)
	payload = bytesField(payload, 2, nil)
	payload = bytesField(payload, 3, nil) // Later protobuf oneof branch wins.
	session, err := ParsePasswordSession(payload, time.Unix(100, 0))
	var rejected *LoginError
	if session != nil || !errors.As(err, &rejected) || rejected.Status != 1 || rejected.Branch != 3 {
		t.Fatalf("non-success final branch authenticated: session=%v, error=%v", session != nil, err)
	}
}

func TestPasswordSuccessCannotAcceptFailedTokenService(t *testing.T) {
	bundle := stringField(nil, 1, "local-unit-fixture-not-a-live-token")
	bundle = varintField(bundle, 3, 0)
	identity := stringField(nil, 1, "11223344-5566-7788-99aa-bbccddeeff00")
	identity = stringField(identity, 2, "local-unit-fixture")
	identity = bytesField(identity, 6, bundle)
	success := bytesField(nil, 1, identity)
	payload := varintField(nil, 1, 1)
	payload = bytesField(payload, 2, success)
	if session, err := ParsePasswordSession(payload, time.Unix(100, 0)); err == nil || session != nil {
		t.Fatalf("failed native token-service response authenticated: session=%v, error=%v", session != nil, err)
	}
}

func TestFriendsRejectsArgosFacadeFailuresBeforeTransport(t *testing.T) {
	// Unit-only state never leaves this process: this client has no connection.
	// The bug would enter native transport instead of rejecting facade failure.
	client := Client{username: "unit-only"}
	session := &account.NativeSession{
		UserID: "unit-only", Username: "unit-only", RefreshToken: "unit-only",
		Tokens: []account.AccessToken{{
			Token: "unit-only-not-server-issued", Scope: APIGatewayScope,
			RetrievedAt: 0, ExpiresAt: 1 << 62,
		}},
	}
	for _, sample := range []struct {
		name    string
		headers map[string]string
	}{
		{"strict-only", map[string]string{"x-snapchat-argos-strict-enforcement": "true"}},
		{"empty-signature", map[string]string{"x-snapchat-att-token": "unit-only-not-server-issued", "x-snapchat-att-sign": ""}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			snapshot, err := client.AllFriends(context.Background(), session, RequestAttestation{
				RequestID: "unit-only", Headers: sample.headers,
			})
			if !errors.Is(err, errIncompleteArgos) || snapshot.Full {
				t.Fatalf("incomplete native Argos output was usable: full=%t, error=%v", snapshot.Full, err)
			}
		})
	}
}

func testArgosPolicy(token []byte, scalar2, scalar3, tokenType uint64) []byte {
	value := bytesField(nil, 1, token)
	value = varintField(value, 2, scalar2)
	value = varintField(value, 3, scalar3)
	return varintField(value, 4, tokenType)
}

func TestArgosResponseRequiresUsableHotToken(t *testing.T) {
	raw := []byte("unit-only-not-server-issued")
	for _, sample := range []struct {
		name    string
		payload []byte
	}{
		{"missing", nil},
		{"cold-only-type-1", bytesField(nil, 3, testArgosPolicy(raw, 1, 2, 1))},
		{"cold-only-type-6", bytesField(nil, 3, testArgosPolicy(raw, 1, 2, 6))},
		{"hot-type-0", bytesField(nil, 2, testArgosPolicy(raw, 1, 2, 0))},
		{"hot-type-1", bytesField(nil, 2, testArgosPolicy(raw, 1, 2, 1))},
		{"hot-type-3", bytesField(nil, 2, testArgosPolicy(raw, 1, 2, 3))},
		{"hot-type-6", bytesField(nil, 2, testArgosPolicy(raw, 1, 2, 6))},
		{"unknown-hot-type", bytesField(nil, 2, testArgosPolicy(raw, 1, 2, 99))},
		{"empty-hot-token", bytesField(nil, 2, testArgosPolicy(nil, 1, 2, 2))},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if _, err := parseArgosTokens(sample.payload); err == nil {
				t.Fatal("unusable hot token was accepted as Argos success")
			}
		})
	}
}

func TestArgosResponsePreservesRawTokensAndOpaquePolicies(t *testing.T) {
	// Binary unit fixtures are neither Base64 text nor server-issued material.
	hotRaw := []byte{0xff, 0x00, 0xfb}
	coldRaw := []byte{0x00, 0xfe}
	for _, sample := range []struct {
		name string
		hot  uint64
		cold uint64
	}{
		{"signed-hot-cold-1", 2, 1},
		{"signed-hot-cold-6", 2, 6},
		{"unsigned-hot-4-cold-1", 4, 1},
		{"unsigned-hot-4-cold-6", 4, 6},
		{"unsigned-hot-5-cold-1", 5, 1},
		{"unsigned-hot-5-cold-6", 5, 6},
	} {
		t.Run(sample.name, func(t *testing.T) {
			payload := bytesField(nil, 2, testArgosPolicy(hotRaw, ^uint64(0), 7, sample.hot))
			payload = bytesField(payload, 3, testArgosPolicy(coldRaw, 9, ^uint64(0), sample.cold))
			tokens, err := parseArgosTokens(payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tokens.hot.token, hotRaw) || tokens.hot.scalar2 != ^uint64(0) || tokens.hot.scalar3 != 7 || tokens.hot.tokenType != sample.hot {
				t.Fatal("raw hot bytes or opaque policy scalars were reinterpreted")
			}
			if !tokens.hasCold || !bytes.Equal(tokens.cold.token, coldRaw) || tokens.cold.scalar2 != 9 || tokens.cold.scalar3 != ^uint64(0) || tokens.cold.tokenType != sample.cold {
				t.Fatal("separate accepted cold policy was lost or substituted for hot")
			}
		})
	}
}

func TestArgosDuplicatePolicyFieldsUseFinalValues(t *testing.T) {
	final := []byte("unit-only-final")
	policy := testArgosPolicy([]byte("unit-only-prior"), 42, 77, 1)
	policy = bytesField(policy, 1, final)
	policy = varintField(policy, 2, 0)
	policy = varintField(policy, 3, ^uint64(0))
	policy = varintField(policy, 4, 4)
	tokens, err := parseArgosTokens(bytesField(nil, 2, policy))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tokens.hot.token, final) || tokens.hot.scalar2 != 0 || tokens.hot.scalar3 != ^uint64(0) || tokens.hot.tokenType != 4 {
		t.Fatal("earlier token/policy occurrence overrode the final bytes or scalar")
	}
}

func TestArgosDuplicatePolicyMessagesMergeWithoutStaleValues(t *testing.T) {
	first := testArgosPolicy([]byte("unit-only-prior"), 42, 77, 2)
	final := bytesField(nil, 1, []byte("unit-only-final"))
	final = varintField(final, 2, 0)
	final = varintField(final, 4, 5)
	payload := bytesField(nil, 2, first)
	payload = bytesField(payload, 2, final)
	tokens, err := parseArgosTokens(payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(tokens.hot.token) != "unit-only-final" || tokens.hot.scalar2 != 0 || tokens.hot.scalar3 != 77 || tokens.hot.tokenType != 5 {
		t.Fatal("duplicate singular policy messages did not merge with final scalar/bytes values")
	}
	for _, sample := range []struct {
		name   string
		update []byte
	}{
		{"cleared-token", bytesField(nil, 1, nil)},
		{"rejected-final-type", varintField(nil, 4, 6)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if _, err := parseArgosTokens(bytesField(bytesField(nil, 2, first), 2, sample.update)); err == nil {
				t.Fatal("usable earlier hot policy masked an unusable final token/type")
			}
		})
	}
}

func TestArgosMalformedResponseCannotPublishHotToken(t *testing.T) {
	valid := bytesField(nil, 2, testArgosPolicy([]byte("unit-only-not-server-issued"), 1, 2, 2))
	for _, sample := range []struct {
		name    string
		payload []byte
	}{
		{"hot-integer", varintField(nil, 2, 2)},
		{"cold-integer", varintField(valid, 3, 1)},
		{"token-integer", bytesField(nil, 2, varintField(nil, 1, 1))},
		{"policy-bytes", bytesField(nil, 2, bytesField(nil, 2, nil))},
		{"third-scalar-bytes", bytesField(nil, 2, bytesField(nil, 3, nil))},
		{"type-bytes", bytesField(nil, 2, bytesField(nil, 4, nil))},
		{"truncated-token", bytesField(nil, 2, []byte{0x0a, 0x02, 0x01})},
		{"truncated-policy", bytesField(valid, 3, []byte{0x10, 0x80})},
		{"truncated-response", append(append([]byte(nil), valid...), 0x80)},
		{"superseded-corruption", append(bytesField(nil, 2, []byte{0x0a, 0x02, 0x01}), valid...)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if _, err := parseArgosTokens(sample.payload); err == nil {
				t.Fatal("malformed Argos response produced a usable hot token")
			}
		})
	}
}

func TestPasswordRejectionPreservesCurrentBranchPublicReason(t *testing.T) {
	// Unit error data, not pinned production wording or a challenge/session.
	initial := varintField(nil, 1, 16)
	initial = bytesField(initial, 11, stringField(nil, 1, "unit-prior-reason"))
	for _, sample := range []struct {
		name   string
		update []byte
		branch protowire.Number
		reason string
	}{
		{"empty-message-merge", bytesField(nil, 11, nil), 11, "unit-prior-reason"},
		{"final-public-reason", bytesField(nil, 11, stringField(nil, 1, "unit-current-reason")), 11, "unit-current-reason"},
		{"explicitly-cleared-reason", bytesField(nil, 11, stringField(nil, 1, "")), 11, ""},
		{"changed-oneof", bytesField(nil, 3, nil), 3, ""},
	} {
		t.Run(sample.name, func(t *testing.T) {
			payload := append(append([]byte(nil), initial...), sample.update...)
			session, err := ParsePasswordSession(payload, time.Unix(100, 0))
			var rejected *LoginError
			if session != nil || !errors.As(err, &rejected) || rejected.Status != 16 || rejected.Branch != sample.branch || rejected.Message != sample.reason {
				t.Fatalf("current rejected branch/public data lost or stale: session=%v, error=%v", session != nil, err)
			}
		})
	}
	corrupt := bytesField(varintField(nil, 1, 16), 11, varintField(nil, 1, 5))
	var rejected *LoginError
	if session, err := ParsePasswordSession(corrupt, time.Unix(100, 0)); session != nil || err == nil || errors.As(err, &rejected) {
		t.Fatal("malformed LH7 string was classified as a valid server rejection")
	}
}

func TestPasswordSuccessMergesSplitMessagesAndResetsOneof(t *testing.T) {
	// Owned offline protocol fixtures, never server-issued sessions.
	firstBundle := stringField(nil, 1, "owned-unit-refresh-not-server-issued")
	lastBundle := varintField(nil, 3, 1)
	firstIdentity := stringField(nil, 1, "owned-unit-user-id")
	firstIdentity = bytesField(firstIdentity, 6, firstBundle)
	lastIdentity := stringField(nil, 2, "owned-unit-prior-name")
	lastIdentity = bytesField(lastIdentity, 6, lastBundle)
	firstSuccess := bytesField(nil, 1, firstIdentity)
	firstSuccess = bytesField(firstSuccess, 1, lastIdentity)
	lastSuccess := bytesField(nil, 1, stringField(nil, 2, "owned-unit-current-name"))
	payload := bytesField(varintField(nil, 1, 1), 2, firstSuccess)
	payload = bytesField(payload, 2, lastSuccess)
	session, err := ParsePasswordSession(payload, time.Unix(100, 0))
	if err != nil || session == nil || session.UserID != "owned-unit-user-id" || session.Username != "owned-unit-current-name" || session.RefreshToken != "owned-unit-refresh-not-server-issued" {
		t.Fatalf("valid split native account/session was lost: session=%v, error=%v", session != nil, err)
	}
	// A branch switch must discard all prior identity/token message state.
	reset := bytesField(varintField(nil, 1, 1), 2, firstSuccess)
	reset = bytesField(reset, 3, nil)
	reset = bytesField(reset, 2, lastSuccess)
	if session, err := ParsePasswordSession(reset, time.Unix(100, 0)); session != nil || err == nil {
		t.Fatal("later incomplete success inherited another oneof branch's identity/tokens")
	}
}

func TestPasswordSessionMergesSplitTokenTiming(t *testing.T) {
	// Owned protocol fixture; split ICi messages preserve both timing offsets.
	bundle := stringField(nil, 1, "owned-unit-refresh-not-server-issued")
	access := stringField(nil, 1, "owned-unit-access-not-server-issued")
	access = stringField(access, 2, APIGatewayScope)
	access = varintField(access, 3, 100)
	bundle = bytesField(bundle, 2, access)
	bundle = varintField(bundle, 3, 1)
	bundle = bytesField(bundle, 4, varintField(nil, 1, 17))
	bundle = bytesField(bundle, 4, varintField(nil, 2, 29))
	identity := stringField(nil, 1, "owned-unit-user-id")
	identity = stringField(identity, 2, "owned-unit-user")
	identity = bytesField(identity, 6, bundle)
	payload := bytesField(varintField(nil, 1, 1), 2, bytesField(nil, 1, identity))
	session, err := ParsePasswordSession(payload, time.Unix(1000, 0))
	if err != nil || session == nil || len(session.Tokens) != 1 {
		t.Fatalf("valid split token timing rejected: session=%v, error=%v", session != nil, err)
	}
	token := session.Tokens[0]
	if token.RetrievedAt != 1000 || token.ExpiresAt != 1083 || token.PrefetchAt != 1071 {
		t.Fatalf("merged timing lost an offset: retrieved=%d expiry=%d prefetch=%d", token.RetrievedAt, token.ExpiresAt, token.PrefetchAt)
	}
}

func TestPasswordSessionPreservesMergedSDKToken(t *testing.T) {
	// Owned wire fixture only. No actual session or native/network attestation.
	bundle := varintField(stringField(nil, 1, "owned-unit-refresh-not-server-issued"), 3, 1)
	identity := stringField(stringField(nil, 1, "owned-unit-user-id"), 2, "owned-unit-user")
	identity = bytesField(identity, 6, bundle)
	base := bytesField(nil, 1, identity)
	first := stringField(stringField(nil, 1, "owned-unit-prior-sdk-id"), 2, "owned-unit-prior-sdk-secret")
	body := bytesField(base, 7, bytesField(nil, 1, first))
	body = bytesField(body, 7, bytesField(nil, 1, stringField(nil, 1, "owned-unit-current-sdk-id")))
	for _, value := range []string{"owned-unit-current-sdk-secret", ""} {
		update := bytesField(nil, 7, bytesField(nil, 1, stringField(nil, 2, value)))
		reply := bytesField(varintField(nil, 1, 1), 2, body)
		reply = bytesField(reply, 2, update)
		session, err := ParsePasswordSession(reply, time.Unix(100, 0))
		if err != nil || session == nil || session.DeviceToken == nil {
			t.Fatalf("merged server SDK token lost: session=%v, error=%v", session != nil, err)
		}
		if session.DeviceToken.ID != "owned-unit-current-sdk-id" || session.DeviceToken.Value != value {
			t.Fatal("SDK token kept superseded fields or failed to apply an explicit empty value")
		}
		// An intervening oneof switch must not leak the old SDK token into
		// a later complete success that has no device-token initialization.
		replaced := bytesField(reply, 3, nil)
		replaced = bytesField(replaced, 2, base)
		session, err = ParsePasswordSession(replaced, time.Unix(100, 0))
		if err != nil || session == nil || session.DeviceToken != nil {
			t.Fatalf("SDK token crossed a oneof replacement: session=%v, error=%v", session != nil, err)
		}
	}
}

func TestMalformedSDKTokenCannotPublishAuthenticatedSession(t *testing.T) {
	bundle := varintField(stringField(nil, 1, "owned-unit-refresh-not-server-issued"), 3, 1)
	identity := stringField(stringField(nil, 1, "owned-unit-user-id"), 2, "owned-unit-user")
	identity = bytesField(identity, 6, bundle)
	for _, initialization := range [][]byte{
		varintField(nil, 1, 5),
		bytesField(nil, 1, varintField(nil, 2, 5)),
		bytesField(nil, 1, []byte{0x0a, 0x02, 0x01}),
	} {
		body := bytesField(bytesField(nil, 1, identity), 7, initialization)
		reply := bytesField(varintField(nil, 1, 1), 2, body)
		if session, err := ParsePasswordSession(reply, time.Unix(100, 0)); err == nil || session != nil {
			t.Fatal("malformed SDK token published an authenticated session")
		}
	}
}

func TestFullSnapshotMergesOutgoingAndMetadataMessages(t *testing.T) {
	first := bytesField(nil, 1, stringField(nil, 1, "owned-unit-sync-token"))
	first = bytesField(first, 2, testRelationship(testUUID(91, 92), "owned-unit-first", 2))
	last := bytesField(nil, 1, varintField(nil, 2, 2))
	last = bytesField(last, 2, testRelationship(testUUID(93, 94), "owned-unit-second", 2))
	snapshot, err := ParseFullFriends(bytesField(bytesField(nil, 1, first), 1, last))
	if err != nil || !snapshot.Full || snapshot.SyncToken != "owned-unit-sync-token" || len(snapshot.Friends) != 2 {
		t.Fatalf("valid split FULL snapshot lost relationships or sync state: %+v, %v", snapshot, err)
	}
}

func TestFullSnapshotMergesSplitRelationshipUUID(t *testing.T) {
	high := uint64(0x1122334455667788)
	low := uint64(0x99aabbccddeeff00)
	highMessage := protowire.AppendFixed64(protowire.AppendTag(nil, 1, protowire.Fixed64Type), high)
	lowMessage := protowire.AppendFixed64(protowire.AppendTag(nil, 2, protowire.Fixed64Type), low)
	relationship := bytesField(nil, 1, highMessage)
	relationship = bytesField(relationship, 1, lowMessage)
	relationship = stringField(relationship, 2, "owned-unit-friend")
	relationship = varintField(relationship, 4, 2)
	snapshot, err := ParseFullFriends(testFullResponse(2, relationship))
	if err != nil || !snapshot.Full || len(snapshot.Friends) != 1 || snapshot.Friends[0].UserID != "11223344-5566-7788-99aa-bbccddeeff00" {
		t.Fatalf("split account UUID lost relationship identity: snapshot=%+v, error=%v", snapshot, err)
	}
}

func testFideliusKeys(t *testing.T, scalar byte) account.FideliusKeys {
	t.Helper()
	var raw [32]byte
	raw[31] = scalar
	key, err := ecdh.P256().NewPrivateKey(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return account.FideliusKeys{IWEK: bytes.Repeat([]byte{scalar}, 32), PrivateKeyPKCS8: private, PublicKeySPKI: public}
}

func testFideliusBinding(iwek, public []byte) []byte {
	mac := hmac.New(sha256.New, iwek)
	mac.Write(public)
	return mac.Sum(nil)
}

func TestBuildPasswordLoginPreservesOriginalNestedHeaderMessages(t *testing.T) {
	input := PasswordInput{
		Credentials: account.Credentials{Username: "unit-user", Password: "unit-password"},
		Installation: account.Installation{
			ClientID: "unit-client", InstanceUUID: "unit-instance",
		},
		Fidelius: testFideliusKeys(t, 1),
		Context: PasswordContext{
			FlowID: "unit-flow", AuthenticationSessionID: "unit-auth",
			AttemptID: "unit-attempt", NetworkRequestID: "unit-network", NumAttempts: 2,
		},
		AndroidIdentifier: []byte{0, 1, 2, 3, 4, 5, 6, 7},
		FideliusVersion:   10,
		Attestation:       []byte("unit-attestation"),
		CofRoutingTag:     "unit-route",
		CofETag:           "unit-etag",
		CofBitmap:         []byte{8, 9},
		SequenceIDs:       []int32{96, 101},
		CloudAccountID:    "unit-cloud-account",
		DeviceTokenID:     "unit-device",
		ClientIntegrityResults: [][]byte{
			[]byte("unit-integrity"),
		},
	}
	payload, err := BuildPasswordLogin(input)
	if err != nil {
		t.Fatal(err)
	}
	header, present, err := messageField(payload, 15)
	if err != nil || !present {
		t.Fatalf("login header missing: present=%t, error=%v", present, err)
	}
	cloud, present, err := messageField(header, 8)
	if err != nil || !present || string(cloud) != input.CloudAccountID {
		t.Fatalf("cloud account ID mismatch: present=%t, value=%q, error=%v", present, cloud, err)
	}
	sequencePayload, present, err := messageField(header, 7)
	if err != nil || !present {
		t.Fatalf("sequence message missing: present=%t, error=%v", present, err)
	}
	var sequences []uint64
	d := decoder{rest: sequencePayload}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number != 1 {
			t.Fatalf("unexpected sequence field %d", entry.number)
		}
		value, valueErr := entry.asVarint()
		if valueErr != nil {
			t.Fatal(valueErr)
		}
		sequences = append(sequences, value)
	}
	if d.err != nil || len(sequences) != 2 || sequences[0] != 96 || sequences[1] != 101 {
		t.Fatalf("sequence message mismatch: %v, %v", sequences, d.err)
	}
	devicePayload, present, err := messageField(header, 10)
	if err != nil || !present {
		t.Fatalf("device message missing: present=%t, error=%v", present, err)
	}
	device, present, err := messageField(devicePayload, 1)
	if err != nil || !present || string(device) != input.DeviceTokenID {
		t.Fatalf("device message mismatch: present=%t, value=%q, error=%v", present, device, err)
	}
	integrity, present, err := messageField(header, 14)
	if err != nil || !present || string(integrity) != "unit-integrity" {
		t.Fatalf("integrity result mismatch: present=%t, value=%q, error=%v", present, integrity, err)
	}
	configuration, present, err := messageField(payload, 8)
	if err != nil || !present {
		t.Fatalf("COF configuration missing: present=%t, error=%v", present, err)
	}
	routing, present, err := messageField(configuration, 1)
	if err != nil || !present || string(routing) != input.CofRoutingTag {
		t.Fatalf("COF routing tag mismatch: present=%t, value=%q, error=%v", present, routing, err)
	}
	etag, present, err := messageField(configuration, 2)
	if err != nil || !present || string(etag) != input.CofETag {
		t.Fatalf("COF etag mismatch: present=%t, value=%q, error=%v", present, etag, err)
	}
	bitmap, present, err := messageField(configuration, 4)
	if err != nil || !present || !bytes.Equal(bitmap, input.CofBitmap) {
		t.Fatalf("COF bitmap mismatch: present=%t, value=%x, error=%v", present, bitmap, err)
	}
}

func TestFideliusFinalizationUsesServerBindingAndOwnsStorage(t *testing.T) {
	pending := testFideliusKeys(t, 1)
	serverIWEK := bytes.Repeat([]byte{47}, 32)
	serverBinding := testFideliusBinding(serverIWEK, pending.PublicKeySPKI)
	// Original nano merges split tj8 messages before key finalization.
	response := bytesField(nil, 5, bytesField(nil, 1, serverIWEK))
	response = bytesField(response, 5, bytesField(nil, 2, serverBinding))
	keys, version, err := finalizeFidelius(response, pending, 10, nil)
	if err != nil || version != 10 || !bytes.Equal(keys.IWEK, serverIWEK) || !bytes.Equal(keys.PrivateKeyPKCS8, pending.PrivateKeyPKCS8) || !bytes.Equal(keys.PublicKeySPKI, pending.PublicKeySPKI) {
		t.Fatalf("returned IWEK/binding was not used to finalize the submitted key pair: version=%d, error=%v", version, err)
	}
	expectedPrivate := bytes.Clone(keys.PrivateKeyPKCS8)
	expectedPublic := bytes.Clone(keys.PublicKeySPKI)
	clear(response)
	clear(serverIWEK)
	clear(pending.IWEK)
	clear(pending.PrivateKeyPKCS8)
	clear(pending.PublicKeySPKI)
	if !bytes.Equal(keys.IWEK, bytes.Repeat([]byte{47}, 32)) || !bytes.Equal(keys.PrivateKeyPKCS8, expectedPrivate) || !bytes.Equal(keys.PublicKeySPKI, expectedPublic) {
		t.Fatal("finalized identity borrowed data from a disposed response/submission")
	}
}

func TestFideliusMissingMismatchAndPrivateKeyCannotInitialize(t *testing.T) {
	pending := testFideliusKeys(t, 1)
	serverIWEK := bytes.Repeat([]byte{47}, 32)
	serverBinding := testFideliusBinding(serverIWEK, pending.PublicKeySPKI)
	valid := bytesField(bytesField(nil, 1, serverIWEK), 2, serverBinding)
	other := testFideliusKeys(t, 2)
	wrongPrivate := pending
	wrongPrivate.PrivateKeyPKCS8 = other.PrivateKeyPKCS8
	for _, sample := range []struct {
		name    string
		message []byte
		keys    account.FideliusKeys
	}{
		{"absent", nil, pending},
		{"missing-iwek", bytesField(nil, 5, bytesField(nil, 2, serverBinding)), pending},
		{"missing-hmac", bytesField(nil, 5, bytesField(nil, 1, serverIWEK)), pending},
		{"wrong-binding", bytesField(nil, 5, bytesField(bytesField(nil, 1, serverIWEK), 2, testFideliusBinding(serverIWEK, other.PublicKeySPKI))), pending},
		{"wrong-private-key", bytesField(nil, 5, valid), wrongPrivate},
		{"wrong-iwek-wire-type", bytesField(nil, 5, varintField(nil, 1, 1)), pending},
	} {
		t.Run(sample.name, func(t *testing.T) {
			keys, version, err := finalizeFidelius(sample.message, sample.keys, 10, nil)
			if err == nil || version != 0 || len(keys.IWEK) != 0 || len(keys.PrivateKeyPKCS8) != 0 || len(keys.PublicKeySPKI) != 0 {
				t.Fatal("unbound or inconsistent server identity persisted usable Fidelius keys")
			}
		})
	}
}

func TestFideliusFinalizationResolvesPreviouslyBoundIdentity(t *testing.T) {
	pending := testFideliusKeys(t, 1)
	previous := &account.NativeSession{Fidelius: testFideliusKeys(t, 2), FideliusVersion: 9}
	serverIWEK := bytes.Repeat([]byte{48}, 32)
	binding := testFideliusBinding(serverIWEK, previous.Fidelius.PublicKeySPKI)
	response := bytesField(nil, 5, bytesField(bytesField(nil, 1, serverIWEK), 2, binding))
	keys, version, err := finalizeFidelius(response, pending, 10, previous)
	if err != nil || version != 9 || !bytes.Equal(keys.PrivateKeyPKCS8, previous.Fidelius.PrivateKeyPKCS8) || !bytes.Equal(keys.PublicKeySPKI, previous.Fidelius.PublicKeySPKI) || !bytes.Equal(keys.IWEK, serverIWEK) {
		t.Fatalf("server binding to existing selected-account identity was replaced by a different submission: version=%d, error=%v", version, err)
	}
	if !bytes.Equal(previous.Fidelius.IWEK, bytes.Repeat([]byte{2}, 32)) {
		t.Fatal("finalization mutated the prior session before new state ownership")
	}
}

func TestPasswordChallengeRetainsOpaqueOwnedStateWithoutAuthenticating(t *testing.T) {
	// Challenge contents are deliberately opaque unit data, not an issuer proof.
	challenge := bytesField(nil, 1, []byte("owned-unit-challenge"))
	authSession := []byte("owned-unit-auth-continuation")
	for _, status := range []uint64{7, 9, 17, 18, 21} {
		branch := protowire.Number(8)
		if status == 21 {
			branch = 13
		}
		payload := bytesField(varintField(nil, 1, status), branch, challenge)
		payload = bytesField(payload, 14, authSession)
		session, err := ParsePasswordSession(payload, time.Unix(100, 0))
		var requested *LoginError
		if session != nil || !errors.As(err, &requested) || !bytes.Equal(requested.Challenge, challenge) || !bytes.Equal(requested.AuthSessionPayload, authSession) {
			t.Fatalf("non-authenticating response-bound challenge lost: status=%d, error=%v", status, err)
		}
		clear(payload)
		if !bytes.Equal(requested.Challenge, challenge) || !bytes.Equal(requested.AuthSessionPayload, authSession) {
			t.Fatal("challenge state borrowed the released gRPC response buffer")
		}
	}
}
