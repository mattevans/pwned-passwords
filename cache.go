package hibp

import "time"

// cache holds our our cached hash/compromised pairs results.
var cache map[string]*PwnedStore

// cacheTTL stores the time to live of our cache (2 hours).
var cacheTTL = 2 * time.Hour

// CacheService handles in-memory caching of our hash/compromised pairs.
type CacheService service

// Get will return our stored in-memory hash/compromised pairs, if we have them.
func (s *CacheService) Get(hash string) *PwnedStore {
	// Is our cache expired?
	if s.IsExpired(hash) {
		return nil
	}

	// Use stored results.
	return cache[hash]
}

// Store will save our hash/compromised pairs to a PwnedStore.
func (s *CacheService) Store(hash string, compromised bool) {
	// No cache? Initialize it.
	if cache == nil {
		cache = map[string]*PwnedStore{}
	}

	// Store
	tn := time.Now()
	cache[hash] = &PwnedStore{
		Hash:        hash,
		Compromised: compromised,
		UpdatedAt:   &tn,
	}
}

// IsExpired checks if we have cached hash and that it isn't expired.
func (s *CacheService) IsExpired(hash string) bool {
	// No cache? bail.
	if cache[hash] == nil {
		return true
	}

	// Expired cache? bail.
	lastUpdated := cache[hash].UpdatedAt
	if lastUpdated != nil && lastUpdated.Add(cacheTTL).Before(time.Now()) {
		return true
	}

	return false
}

// Expire will expire the cache for a given hash.
func (s *CacheService) Expire(hash string) {
	cache[hash] = nil
}

// ExpireAll will expire all cache.
func (s *CacheService) ExpireAll() {
	cache = nil
}
