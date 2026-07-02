package session

import (
	"sync"

	"github.com/google/uuid"
)

type Kind string

const (
	KindExec Kind = "exec"
	KindLogs Kind = "logs"
	KindPF   Kind = "pf"
)

type Entry struct {
	ID    string      `json:"id"`
	Kind  Kind        `json:"kind"`
	Stop  func()      `json:"-"`
	Meta  interface{} `json:"meta,omitempty"`
}

type Manager struct {
	mu    sync.Mutex
	items map[string]*Entry
}

func NewManager() *Manager { return &Manager{items: map[string]*Entry{}} }

func (m *Manager) Add(kind Kind, stop func(), meta interface{}) string {
	id := uuid.NewString()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[id] = &Entry{ID: id, Kind: kind, Stop: stop, Meta: meta}
	return id
}

func (m *Manager) Stop(id string) bool {
	m.mu.Lock()
	e, ok := m.items[id]
	if ok {
		delete(m.items, id)
	}
	m.mu.Unlock()
	if ok && e.Stop != nil {
		e.Stop()
	}
	return ok
}

func (m *Manager) Get(id string) *Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.items[id]
}

func (m *Manager) UpdateMeta(id string, meta interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.items[id]; ok {
		e.Meta = meta
	}
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	items := m.items
	m.items = map[string]*Entry{}
	m.mu.Unlock()
	for _, e := range items {
		if e.Stop != nil {
			e.Stop()
		}
	}
}

func (m *Manager) List(kind Kind) []*Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*Entry{}
	for _, e := range m.items {
		if kind == "" || e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}
