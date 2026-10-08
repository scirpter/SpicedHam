package account

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials are read only from the user's local account configuration.
// They are never included in the persisted native installation/session state.
type Credentials struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func ReadCredentials(path string) ([]Credentials, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var document struct {
		Accounts []Credentials `json:"accounts"`
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("account configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("account configuration contains trailing JSON")
	}
	if len(document.Accounts) == 0 {
		return nil, errors.New("account configuration is empty")
	}
	names := make(map[string]struct{}, len(document.Accounts))
	for _, entry := range document.Accounts {
		if entry.Name == "" || entry.Username == "" || entry.Password == "" {
			return nil, errors.New("each account needs name, username and password")
		}
		if _, present := names[entry.Name]; present {
			return nil, fmt.Errorf("duplicate account name %q", entry.Name)
		}
		names[entry.Name] = struct{}{}
	}
	return document.Accounts, nil
}

type Installation struct {
	ClientID     string `json:"client_id"`
	ClientIDAtMS int64  `json:"client_id_at_ms"`
	InstanceUUID string `json:"instance_uuid"`
	// SSAIDUserKey belongs to this account's isolated software-port logical user,
	// independent of Fidelius submissions, ClientID rotation or a handset.
	SSAIDUserKey []byte `json:"ssaid_user_key"`
	// CloudAccountID is the app-scoped Janus cloud-account identifier. The
	// original Android client generates it once and reuses it for login requests.
	CloudAccountID string `json:"cloud_account_id"`
}

// FideliusKeys hold tentative submission material or server-bound finalized keys.
// Authentication alone does not bind keys: finalized IWEK/SPKI HMAC must match.
type FideliusKeys struct {
	IWEK            []byte `json:"iwek"`
	PrivateKeyPKCS8 []byte `json:"private_key_pkcs8"`
	PublicKeySPKI   []byte `json:"public_key_spki"`
}

type AccessToken struct {
	Token       string `json:"token"`
	Scope       string `json:"scope"`
	RetrievedAt int64  `json:"retrieved_at"`
	ExpiresAt   int64  `json:"expires_at"`
	PrefetchAt  int64  `json:"prefetch_at"`
}

// DeviceToken is the SDK id/secret from xP1.field7 -> hIh.field1 -> TU6.
// It is distinct from refresh/access tokens and is never generated locally.
type DeviceToken struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// A server-issued refresh token is not the locally generated P4c authenticationSessionId.
type NativeSession struct {
	UserID          string        `json:"user_id"`
	Username        string        `json:"username"`
	RefreshToken    string        `json:"refresh_token"`
	Tokens          []AccessToken `json:"access_tokens"`
	DeviceToken     *DeviceToken  `json:"device_token,omitempty"`
	Fidelius        FideliusKeys  `json:"fidelius"`
	FideliusVersion int64         `json:"fidelius_version"`
}

type Friend struct {
	UserID         string `json:"user_id"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	LegacyUsername string `json:"legacy_username,omitempty"`
}

// Full marks a successfully applied FULL Atlas snapshot, not a received HTTP response.
type FriendSnapshot struct {
	Full      bool     `json:"full"`
	SyncToken string   `json:"sync_token"`
	Friends   []Friend `json:"friends"`
}

type State struct {
	Version      int            `json:"version"`
	AccountName  string         `json:"account_name"`
	Username     string         `json:"username"`
	Installation Installation   `json:"installation"`
	Session      *NativeSession `json:"session,omitempty"`
	Friends      FriendSnapshot `json:"friends"`
}

type Store struct {
	directory string
	name      string
	username  string
	key       [32]byte
}

func NewStore(directory string, credentials Credentials) (*Store, error) {
	if directory == "" || credentials.Name == "" || credentials.Username == "" {
		return nil, errors.New("session store requires directory and account identity")
	}
	username := strings.ToLower(credentials.Username)
	key := sha256.Sum256([]byte("snapnative-account-v1\x00" + credentials.Name + "\x00" + username))
	return &Store{directory: directory, name: credentials.Name, username: username, key: key}, nil
}

func (s *Store) Path() string {
	return filepath.Join(s.directory, hex.EncodeToString(s.key[:])+".session")
}

func (s *Store) Load() (*State, error) {
	sealed, err := os.ReadFile(s.Path())
	if err != nil {
		return nil, err
	}
	plaintext, err := unprotectState(sealed, s.key[:])
	if err != nil {
		return nil, fmt.Errorf("decrypt this account's session: %w", err)
	}
	defer clear(plaintext)
	var state State
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("decode stored native session: %w", err)
	}
	if err := s.check(&state); err != nil {
		return nil, err
	}
	createdSSAID, err := state.Installation.ensureSSAIDUserKey()
	if err != nil {
		return nil, err
	}
	createdCloudAccountID, err := state.Installation.ensureCloudAccountID()
	if err != nil {
		return nil, err
	}
	if createdSSAID || createdCloudAccountID {
		// Older v1 state may omit additive account-scoped installation values.
		if err := s.Save(&state); err != nil {
			return nil, fmt.Errorf("persist migrated installation identity: %w", err)
		}
	}
	return &state, nil
}

func (s *Store) Save(state *State) error {
	if err := s.check(state); err != nil {
		return err
	}
	if _, err := state.Installation.ensureSSAIDUserKey(); err != nil {
		return err
	}
	if _, err := state.Installation.ensureCloudAccountID(); err != nil {
		return err
	}
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	sealed, err := protectState(plaintext, s.key[:])
	if err != nil {
		return fmt.Errorf("protect this account's native state: %w", err)
	}
	if err := os.MkdirAll(s.directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(s.directory, ".native-state-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(sealed); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return replaceStateFile(name, s.Path())
}

func (s *Store) check(state *State) error {
	if state == nil || state.Version != 1 || state.AccountName != s.name || state.Username != s.username {
		return errors.New("native state belongs to a different account or format")
	}
	if state.Session != nil && (state.Session.UserID == "" || state.Session.RefreshToken == "" || strings.ToLower(state.Session.Username) != s.username) {
		return errors.New("native session has no matching authenticated account and refresh token")
	}
	return nil
}

func (s *Store) LoadOrCreate(now time.Time) (*State, error) {
	state, err := s.Load()
	if err == nil {
		age := now.UnixMilli() - state.Installation.ClientIDAtMS
		if age >= 0 && age < 30*24*60*60*1000 {
			return state, nil
		}
		id, err := FreshUUID()
		if err != nil {
			return nil, err
		}
		state.Installation.ClientID, state.Installation.ClientIDAtMS = id, now.UnixMilli()
		return state, s.Save(state)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err // Never silently replace an unreadable authenticated session.
	}
	installation, err := newInstallation(now)
	if err != nil {
		return nil, err
	}
	state = &State{Version: 1, AccountName: s.name, Username: s.username, Installation: installation}
	return state, s.Save(state)
}

// The APK's qzl.a constructs a UUID from two random longs without UUIDv4 masks.
func FreshUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	var encoded [32]byte
	hex.Encode(encoded[:], raw[:])
	return string(encoded[:8]) + "-" + string(encoded[8:12]) + "-" + string(encoded[12:16]) + "-" + string(encoded[16:20]) + "-" + string(encoded[20:]), nil
}

func newInstallation(now time.Time) (Installation, error) {
	clientID, err := FreshUUID()
	if err != nil {
		return Installation{}, err
	}
	instanceUUID, err := FreshUUID()
	if err != nil {
		return Installation{}, err
	}
	installation := Installation{ClientID: clientID, ClientIDAtMS: now.UnixMilli(), InstanceUUID: instanceUUID}
	if _, err := installation.ensureSSAIDUserKey(); err != nil {
		return Installation{}, err
	}
	return installation, nil
}

// NewFideliusKeys follows Tk8.a for top-level or fresh COS-stage initialization.
// Direct nonce challenges retain their pending keys; COS starts a new key stage.
func NewFideliusKeys() (FideliusKeys, error) {
	pending := FideliusKeys{IWEK: make([]byte, 32)}
	complete := false
	defer func() {
		if !complete {
			clear(pending.IWEK)
			clear(pending.PrivateKeyPKCS8)
			clear(pending.PublicKeySPKI)
		}
	}()
	if _, err := rand.Read(pending.IWEK); err != nil {
		return FideliusKeys{}, err
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return FideliusKeys{}, err
	}
	pending.PrivateKeyPKCS8, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return FideliusKeys{}, err
	}
	pending.PublicKeySPKI, err = x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		return FideliusKeys{}, err
	}
	complete = true
	return pending, nil
}
