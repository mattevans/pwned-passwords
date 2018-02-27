package hibp

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PwnedService handles retrieving pwned hashes from in-memory cache or
// by fetching fresh results.
type PwnedService service

// PwnedStore holds our pwned password hashes and compromised status.
type PwnedStore struct {
	Hash        string     `json:"hash"`
	Compromised bool       `json:"compromised"`
	UpdatedAt   *time.Time `json:"updated_at"`
}

// Compromised will build and execute a request to HIBP to check to see
// if the passed value is compromised or not.
func (s *PwnedService) Compromised(value string) (bool, error) {
	var err error

	// Our value being checked is empty, we don't want that.
	if value == "" {
		return false, errors.New("Value for compromised check cannot be empty")
	}

	// SHA-1 hash our input value.
	hashedStr := _hashString(value)

	// If we have cached results, use them.
	cache := s.client.Cache.Get(hashedStr)
	if cache != nil {
		hashedStr = cache.Hash
		return cache.Compromised, err
	}

	// Pop our prefix and suffix.
	prefix := strings.ToUpper(hashedStr[:5])
	suffix := strings.ToUpper(hashedStr[5:])

	// Build request.
	request, err := s.client.NewRequest("GET", fmt.Sprintf("range/%s", prefix), nil)
	if err != nil {
		return false, err
	}

	// Make request.
	response, err := s.client.Do(request)
	if err != nil {
		return false, err
	}

	// Range our response ([]string).
	for _, target := range response {
		// If our target, minus the compromised count matches our suffix.
		if string(target[:35]) == suffix {
			_, err = strconv.ParseInt(target[36:], 10, 64)
			if err != nil {
				return false, err
			}

			// Store in cache as compromised.
			s.client.Cache.Store(hashedStr, true)

			// Return.
			return true, err
		}
	}

	// Store in cache as non-compromised.
	s.client.Cache.Store(hashedStr, false)

	// Return.
	return false, err
}

// _hashString will return a sha1 hash of the given value.
func _hashString(value string) string {
	alg := sha1.New()
	alg.Write([]byte(value))
	return strings.ToUpper(hex.EncodeToString(alg.Sum(nil)))
}
