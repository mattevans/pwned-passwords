package hibp

import (
	gc "github.com/patrickmn/go-cache"
)

// StoreService handles in-memory caching of our hashed results.
type StoreService struct {
	client *Client
	store  *gc.Cache
}

// StoredHash holds our pwned password hashes and compromised status.
type StoredHash struct {
	Hash        string `json:"hash"`
	Compromised bool   `json:"compromised"`
}

// NewStoreService creates a new handler for this service.
func NewStoreService(
	client *Client,
	store *gc.Cache,
) *StoreService {
	return &StoreService{
		client,
		store,
	}
}

// Get will return our in-memory stored pwnd result.
func (s *StoreService) Get(hash string) (*StoredHash, bool) {
	if x, found := s.store.Get(hash); found {
		return x.(*StoredHash), found
	}
	return nil, false
}

// Store will store our pwnd result in-memory.
func (s *StoreService) Store(hash string, compromised bool) {
	toStore := &StoredHash{
		Hash:        hash,
		Compromised: compromised,
	}
	s.store.Set(
		hash,
		toStore,
		gc.DefaultExpiration,
	)
}

// IsExpired checks whether or not the given hash is stored and expired.
func (s *StoreService) IsExpired(hash string) bool {
	if _, found := s.store.Get(hash); found {
		return false
	}
	return true
}

// Expire will expire the cache for a given hash.
func (s *StoreService) Expire(hash string) {
	s.store.Delete(hash)
}

// ExpireAll will expire all cache.
func (s *StoreService) ExpireAll() {
	s.store.Flush()
}
