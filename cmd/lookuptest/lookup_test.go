package main

import (
	"math/rand"
	"testing"
)

// Struct key
type Key struct {
	Part1 uint32
	Part2 int32
}

// Function to encode key as uint64
func encodeKey(part1 uint32, part2 int32) uint64 {
	return (uint64(part1) << 32) | uint64(uint32(part2))
}

// Generate random keys
func generateTestData(n int) ([]Key, []uint64) {
	structKeys := make([]Key, n)
	uint64Keys := make([]uint64, n)

	for i := 0; i < n; i++ {
		part1 := uint32(rand.Intn(1000000))
		part2 := int32(rand.Intn(2000000) - 1000000) // range: [-1000000, 1000000]
		structKeys[i] = Key{part1, part2}
		uint64Keys[i] = encodeKey(part1, part2)
	}

	return structKeys, uint64Keys
}

const mapSize = 1000000 // Adjust based on need

// Benchmark using struct as the key
func BenchmarkMapWithStructKey(b *testing.B) {
	// Create map and populate it
	m := make(map[Key]string, mapSize)
	structKeys, _ := generateTestData(mapSize)

	for _, k := range structKeys {
		m[k] = "value"
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m[structKeys[i%mapSize]]
	}
}

// Benchmark using uint64 as the key
func BenchmarkMapWithUint64Key(b *testing.B) {
	// Create map and populate it
	m := make(map[uint64]string, mapSize)
	_, uint64Keys := generateTestData(mapSize)

	for _, k := range uint64Keys {
		m[k] = "value"
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = m[uint64Keys[i%mapSize]]
	}
}
