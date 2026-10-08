package native

// DefaultArgosConfiguration ports Ui0.b/z8h.s with the APK's enabled setting,
// genuine empty config cache and no extra supported-prefix configuration.
// These are routing rules, not a handset profile or a generated attestation.
func DefaultArgosConfiguration() []byte {
	configuration := make([]byte, 0, 1000)
	rule := make([]byte, 0, 500)
	// tFd's field-2 exact matches SELECT a rule; they are not exclusions.
	appendRule := func(prefixes, exactMatches []string, mode uint64, strict bool) {
		rule = rule[:0]
		for _, prefix := range prefixes {
			rule = stringField(rule, 1, prefix)
		}
		for _, match := range exactMatches {
			rule = stringField(rule, 2, match)
		}
		rule = varintField(rule, 3, mode)
		value := uint64(0)
		if strict {
			value = 1
		}
		rule = varintField(rule, 4, value)
		configuration = bytesField(configuration, 1, rule)
	}
	appendRule([]string{
		"/boosts-prod/", "/readreceipt-indexer/", "/streaming-collector/", "/suggest_friend_",
		"/snapchat.friending.server.FriendAction/", "/snapchat.telephony.api.PhoneEnrollmentService/",
	}, []string{"/events_batch", "/snapchat.friending.server.ContactBook/FullSyncContactBookUpload"}, 5, true)
	appendRule([]string{"/messagingcoreservice.MessagingCoreService/"}, nil, 1, false)
	appendRule([]string{
		"/snapchat.music.music_service.MusicService/",
		"/music/snapchat.creativetools.compute.ComputeFeedService/",
		"/music/snapchat.creativetools.userdata.UserDataService/",
		"/snapchat.search.musicservice.SearchService/",
	}, []string{
		"/GetMusicTrack", "/GetMusicTracks", "/GetPlaylist", "/GetPlaylists",
		"/GetFeaturedPlaylist", "/GetPickerLayout", "/GetPickerLayoutPage",
		"/GetMyCustomSoundsPlaylist", "/CheckIsAvailable", "/CreateCustomSound",
		"/UpdateCustomSound", "/DeleteCustomSound", "/UpdateOriginalSound",
	}, 5, true)
	return configuration
}

// BuildPasswordAttestationInput is plaintext nk9 for vkt.h.f, NOT a token.
// An encrypted f result must still be produced from real native collector state.
func BuildPasswordAttestationInput(configuration []byte) []byte {
	payload := make([]byte, 0, len(configuration)+24)
	payload = stringField(payload, 2, "passwordLogin")
	payload = varintField(payload, 3, 1)
	payload = bytesField(payload, 4, configuration)
	payload = bytesField(payload, 5, nil)
	return payload
}
