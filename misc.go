package main

import "sync"

type SyncSet[K comparable] struct {
	m sync.Map
}

func (m *SyncSet[K]) Contains(k K) bool {
	_, ok := m.m.Load(k)
	if !ok {
		return false
	}
	return true
}

func (m *SyncSet[K]) Add(k K) {
	m.m.Store(k, struct{}{})
}

func (m *SyncSet[K]) Remove(k K) bool {
	_, ok := m.m.LoadAndDelete(k)
	return ok
}

func (m *SyncSet[K]) CheckAndRemove(k K) bool {
	_, ok := m.m.LoadAndDelete(k)
	return ok
}

func (m *SyncSet[K]) Delete(k K) {
	m.m.Delete(k)
}

func (m *SyncSet[K]) Range(f func(k K) bool) {
	m.m.Range(func(key, _ any) bool {
		return f(key.(K))
	})
}

type SyncMap[K comparable, V any] struct {
	m sync.Map
}

func (m *SyncMap[K, V]) Load(k K) (V, bool) {
	v, ok := m.m.Load(k)
	if !ok {
		var nv V
		return nv, false
	}
	return v.(V), true
}

func (m *SyncMap[K, V]) Store(k K, v V) {
	m.m.Store(k, v)
}

func (m *SyncMap[K, V]) LoadOrStore(k K, v V) (V, bool) {
	value, ok := m.m.LoadOrStore(k, v)
	return value.(V), ok
}

func (m *SyncMap[K, V]) LoadAndDelete(k K) (V, bool) {
	value, ok := m.m.LoadAndDelete(k)
	if !ok {
		var nv V
		return nv, false
	}
	return value.(V), ok
}

func (m *SyncMap[K, V]) Delete(k K) {
	m.m.Delete(k)
}

func (m *SyncMap[K, V]) Range(f func(k K, v V) bool) {
	m.m.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}
