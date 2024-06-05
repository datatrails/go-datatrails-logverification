package logverification

/**
 * Event Hasher defines an interface that reproduces a hash of a datatrails event
 *   that is present on the merkle log.
 */

type EventHasher interface {
	HashEvent(eventJson []byte) ([]byte, error)
}
