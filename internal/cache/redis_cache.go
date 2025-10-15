// internal/cache/redis_cache.go
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
}

type RedisCache struct {
	client *redis.Client
	prefix string
}

func NewRedisCache(addr, password string, db int) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisCache{
		client: client,
		prefix: "netzilla:",
	}, nil
}

func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	fullKey := r.prefix + key
	data, err := r.client.Get(ctx, fullKey).Bytes()
	if err == redis.Nil {
		return nil, nil // Key doesn't exist
	}
	return data, err
}

func (r *RedisCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	fullKey := r.prefix + key
	
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return r.client.Set(ctx, fullKey, data, expiration).Err()
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	fullKey := r.prefix + key
	return r.client.Del(ctx, fullKey).Err()
}

func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	fullKey := r.prefix + key
	count, err := r.client.Exists(ctx, fullKey).Result()
	return count > 0, err
}

// Memory cache fallback
type MemoryCache struct {
	data map[string][]byte
	ttl  map[string]time.Time
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		data: make(map[string][]byte),
		ttl:  make(map[string]time.Time),
	}
}

func (m *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	// Check if key exists and isn't expired
	if data, exists := m.data[key]; exists {
		if expiry, hasTTL := m.ttl[key]; hasTTL {
			if time.Now().After(expiry) {
				delete(m.data, key)
				delete(m.ttl, key)
				return nil, nil
			}
		}
		return data, nil
	}
	return nil, nil
}

func (m *MemoryCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	m.data[key] = data
	if expiration > 0 {
		m.ttl[key] = time.Now().Add(expiration)
	}
	return nil
}
