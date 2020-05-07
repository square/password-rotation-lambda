// Copyright 2020, Square, Inc.

package rotate

import (
	"time"
)

const (
	EVENT_BEGIN_ROTATION              = "begin-rotation"
	EVENT_BEGIN_PASSWORD_ROTATION     = "begin-password-rotation"
	EVENT_END_PASSWORD_ROTATION       = "end-password-rotation"
	EVENT_BEGIN_PASSWORD_VERIFICATION = "begin-password-verification"
	EVENT_END_PASSWORD_VERIFICATION   = "end-password-verification"
	EVENT_NEW_PASSWORD_IS_CURRENT     = "new-password-is-current"
	EVENT_END_ROTATION                = "end-rotation"
	EVENT_BEGIN_PASSWORD_ROLLBACK     = "begin-password-rollback"
	EVENT_ERROR                       = "error"
)

// Event is an important event during the four-step Secrets Manager rotation process.
type Event struct {
	Name  string    // EVENT_ const
	Step  string    // "createSecret", "setSecret", "testSecret", or "finishSecret"
	Time  time.Time // when event occurred
	Error error     // non-nil if Step failed (Name will be EVENT_ERROR)
}

// EventReceiver receives events from a Rotator during the four-step Secrets Manager
// rotation process.
type EventReceiver interface {
	// Receive receives the Event sent by a Rotator during the four-step Secrets Manager
	// rotation process. If this function blocks, it blocks the rotation process.
	Receive(Event)
}

// NullEventReceiver is the default EventReceiver if none is provided in the Config.
// It ignores all events.
type NullEventReceiver struct{}

var _ EventReceiver = NullEventReceiver{}

func (r NullEventReceiver) Receive(Event) {}
