package native

import (
	"encoding/hex"
	"errors"
	"fmt"

	"snapnative/internal/account"
)

const (
	FriendsHost   = "us-east4-gcp.api.snapchat.com"
	FriendsMethod = "/com.snapchat.atlas.gw.AtlasGw/SyncFriendData"
)

// The initial Atlas request explicitly sends an empty outgoing checkpoint.
// Subsequent checkpoints request deltas, not pages of this FULL snapshot.
func BuildFullFriendsRequest() []byte {
	return []byte{0x1a, 0x02, 0x10, 0x00, 0x2a, 0x02, 0x0a, 0x00}
}

func ParseFullFriends(payload []byte) (account.FriendSnapshot, error) {
	outgoing, present, err := messageField(payload, 1)
	if err != nil {
		return account.FriendSnapshot{}, err
	}
	if !present {
		return account.FriendSnapshot{}, errors.New("Atlas response has no outgoing relationship snapshot")
	}
	metadata, present, err := messageField(outgoing, 1)
	if err != nil {
		return account.FriendSnapshot{}, err
	}
	if !present {
		return account.FriendSnapshot{}, errors.New("Atlas response has no snapshot metadata")
	}
	var snapshot account.FriendSnapshot
	var updateType uint64
	d := decoder{rest: metadata}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		var err error
		switch entry.number {
		case 1:
			var token []byte
			token, err = entry.asBytes()
			snapshot.SyncToken = string(token)
		case 2:
			updateType, err = entry.asVarint()
		}
		if err != nil {
			return account.FriendSnapshot{}, err
		}
	}
	if d.err != nil {
		return account.FriendSnapshot{}, d.err
	}
	if updateType != 2 {
		return account.FriendSnapshot{}, fmt.Errorf("Atlas update type %d is not a complete FULL snapshot", updateType)
	}
	indices := make(map[string]int)
	d = decoder{rest: outgoing}
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		if entry.number != 2 {
			continue
		}
		message, err := entry.asBytes()
		if err != nil {
			return account.FriendSnapshot{}, err
		}
		friend, linkType, err := parseRelationship(message)
		if err != nil {
			return account.FriendSnapshot{}, err
		}
		position, exists := indices[friend.UserID]
		switch linkType {
		case 2: // Apply repeated identities and transitions in server order.
			if exists {
				snapshot.Friends[position] = friend
			} else {
				indices[friend.UserID] = len(snapshot.Friends)
				snapshot.Friends = append(snapshot.Friends, friend)
			}
		case 3, 4, 5, 6:
			if exists {
				last := len(snapshot.Friends) - 1
				delete(indices, friend.UserID)
				if position != last {
					snapshot.Friends[position] = snapshot.Friends[last]
					indices[snapshot.Friends[position].UserID] = position
				}
				snapshot.Friends[last] = account.Friend{}
				snapshot.Friends = snapshot.Friends[:last]
			}
		}
	}
	if d.err != nil {
		return account.FriendSnapshot{}, d.err
	}
	snapshot.Full = true
	return snapshot, nil
}

func parseRelationship(payload []byte) (account.Friend, uint64, error) {
	uuid, hasUUID, err := messageField(payload, 1)
	if err != nil {
		return account.Friend{}, 0, err
	}
	d := decoder{rest: payload}
	var friend account.Friend
	var linkType uint64
	for entry, ok := d.next(); ok; entry, ok = d.next() {
		var err error
		switch entry.number {
		case 2, 3, 36:
			var value []byte
			value, err = entry.asBytes()
			switch entry.number {
			case 2:
				friend.Username = string(value)
			case 3:
				friend.DisplayName = string(value)
			case 36:
				friend.LegacyUsername = string(value)
			}
		case 4:
			linkType, err = entry.asVarint()
		}
		if err != nil {
			return account.Friend{}, 0, err
		}
	}
	if d.err != nil {
		return account.Friend{}, 0, d.err
	}
	if !hasUUID {
		if linkType == 6 {
			return account.Friend{}, 6, nil
		}
		return account.Friend{}, 0, errors.New("non-deleted Atlas relationship has no account UUID")
	}
	identity, err := uuidBytes(uuid)
	if err != nil {
		return account.Friend{}, 0, err
	}
	var printed [36]byte
	hex.Encode(printed[:8], identity[:4])
	printed[8] = '-'
	hex.Encode(printed[9:13], identity[4:6])
	printed[13] = '-'
	hex.Encode(printed[14:18], identity[6:8])
	printed[18] = '-'
	hex.Encode(printed[19:23], identity[8:10])
	printed[23] = '-'
	hex.Encode(printed[24:], identity[10:])
	friend.UserID = string(printed[:])
	return friend, linkType, nil
}
