// SPDX-License-Identifier: AGPL-3.0-only

package social

// Pending-word bits of the console's per-user notification state, in the order
// the client tests them (docs/xbox/social-protocol.md 2.3): the lowest set bit
// picks the poll kind.
const (
	PendingList1   uint32 = 0x1  // poll kind 0: friend list change
	PendingList2   uint32 = 0x2  // poll kind 1: friend list change
	PendingInvite  uint32 = 0x8  // poll kind 3: game invitation received
	PendingAnswer  uint32 = 0x10 // poll kind 4: invitation answered
	PendingPresent uint32 = 0x4  // poll kind 2: friend presence
)

// Push tells the gateway that the signed-in user XUID has something to poll.
type Push struct {
	XUID string
	Bits uint32
}

// PushSource turns hub notices into Push values for users who are online on
// Xbox right now (only they can receive one), calling emit for each. emit must
// not block. Revocations are not pushes; the connection owner handles them.
func PushSource(h *Hub, p *Presences, emit func(Push)) {
	h.Tap(func(n Notice) {
		var bits uint32
		switch n.Kind {
		case NoticeFriendRequested, NoticeFriendAccepted, NoticeFriendRemoved:
			bits = PendingList1
		case NoticeInvitation:
			bits = PendingInvite
		case NoticeAnswer:
			bits = PendingAnswer
		case NoticePresence:
			bits = PendingPresent
		default:
			return
		}
		if x, ok := p.XUIDOf(n.Account); ok {
			emit(Push{x, bits})
		}
	})
}
