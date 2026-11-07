package trust

import "time"

// TimestampGranularity is the precision of the creation times written into
// signed documents, invites, enrollment and key rotation requests (#49):
// rounded down to the minute, so a document copied off the coordinator
// does not tell to the second when the owner or a device acted. Expiry,
// revocation and retirement times keep their own precision because the
// security checks compare them.
const TimestampGranularity = time.Minute

// roundTimestamp rounds t down to TimestampGranularity, in UTC. Rounding
// down never moves a time into the future, so the clock-skew checks of
// Verify stay as they were.
func roundTimestamp(t time.Time) time.Time {
	return t.UTC().Truncate(TimestampGranularity)
}
