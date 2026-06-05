package api

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// Message is a single payload broadcast over the SSE channel.
type Message struct {
	// Type is a stable identifier consumed by the SPA: "event", "ap",
	// "client", "status", "ping". It maps to the SSE `event:` field.
	Type string `json:"type"`
	// Data is the JSON-encodable payload.
	Data any `json:"data"`
}

// Common SSE message type tags.
const (
	MessageTypeEvent  = "event"
	MessageTypeAP     = "ap"
	MessageTypeClient = "client"
	MessageTypeStatus = "status"
)

// NewEventMessage wraps a security event payload as a Message.
func NewEventMessage(payload any) Message {
	return Message{Type: MessageTypeEvent, Data: payload}
}

// NewStatusMessage wraps a status payload as a Message.
func NewStatusMessage(payload any) Message {
	return Message{Type: MessageTypeStatus, Data: payload}
}

// subscriber is a single SSE client connection's receive channel and id.
type subscriber struct {
	id int64
	ch chan Message
}

// Hub is a non-blocking fan-out broadcaster for SSE clients.
//
// Publish enqueues a message to a central channel which is drained by Run
// and forwarded to every active subscriber's channel. Slow subscribers are
// not allowed to block the broadcaster: if a per-subscriber channel is
// full, the message is dropped for that subscriber and a warning is logged.
type Hub struct {
	logger *slog.Logger

	subsMu sync.RWMutex
	subs   map[int64]*subscriber
	nextID atomic.Int64

	// publishQueue is the central producer channel. It is sized so that a
	// short burst of events does not block the producers, but bounded so
	// memory stays predictable.
	publishQueue chan Message

	// subscriberBuffer is the size of each per-subscriber channel.
	subscriberBuffer int
}

// HubOption customizes a Hub. Currently unused; kept for future tuning.
type HubOption func(*Hub)

// NewHub creates a Hub with sensible default buffer sizes.
func NewHub(logger *slog.Logger, opts ...HubOption) *Hub {
	h := &Hub{
		logger:           logger,
		subs:             make(map[int64]*subscriber),
		publishQueue:     make(chan Message, 256),
		subscriberBuffer: 64,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HasSubscribers reports whether at least one subscriber is connected.
// Used by background producers (e.g. periodic state diffs) to skip work
// when no one is listening.
func (h *Hub) HasSubscribers() bool {
	h.subsMu.RLock()
	defer h.subsMu.RUnlock()
	return len(h.subs) > 0
}

// SubscriberCount returns the number of currently connected subscribers.
func (h *Hub) SubscriberCount() int {
	h.subsMu.RLock()
	defer h.subsMu.RUnlock()
	return len(h.subs)
}

// Publish enqueues a message for broadcast. Non-blocking; if the central
// queue is full the message is dropped and a warning is logged.
func (h *Hub) Publish(msg Message) {
	select {
	case h.publishQueue <- msg:
	default:
		h.logger.Warn("api/sse: publish queue full; dropping message",
			"type", msg.Type)
	}
}

// Subscribe registers a new subscriber and returns its read-only channel
// plus an unsubscribe function. The unsubscribe function closes the channel
// and removes the subscriber from the hub. Callers should defer the
// unsubscribe in the same scope as the subscription.
func (h *Hub) Subscribe() (msgs <-chan Message, unsubscribe func()) {
	id := h.nextID.Add(1)
	sub := &subscriber{
		id: id,
		ch: make(chan Message, h.subscriberBuffer),
	}

	h.subsMu.Lock()
	h.subs[id] = sub
	h.subsMu.Unlock()

	unsub := sync.OnceFunc(func() {
		h.subsMu.Lock()
		delete(h.subs, id)
		h.subsMu.Unlock()
		close(sub.ch)
	})
	return sub.ch, unsub
}

// Run drains the publish queue and fans messages out to every subscriber.
// It exits when ctx is canceled, then closes all subscriber channels so
// pending receivers unblock.
func (h *Hub) Run(ctx context.Context) {
	defer h.closeAll()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-h.publishQueue:
			h.broadcast(msg)
		}
	}
}

// broadcast sends msg to every subscriber via non-blocking sends.
func (h *Hub) broadcast(msg Message) {
	h.subsMu.RLock()
	defer h.subsMu.RUnlock()

	for _, sub := range h.subs {
		select {
		case sub.ch <- msg:
		default:
			// Slow consumer: drop this message rather than block the broadcaster.
			h.logger.Warn("api/sse: subscriber buffer full; dropping message",
				"subscriber_id", sub.id, "type", msg.Type)
		}
	}
}

// closeAll closes every subscriber channel and clears the map. Safe to call
// after Run exits because no more sends to subscriber channels will happen.
func (h *Hub) closeAll() {
	h.subsMu.Lock()
	defer h.subsMu.Unlock()
	for _, sub := range h.subs {
		close(sub.ch)
	}
	h.subs = make(map[int64]*subscriber)
}
