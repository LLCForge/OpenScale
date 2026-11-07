package coordinator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/openscale/openscale/internal/securefile"
)

// ErrNoRunningCoordinator means no coordinator picked the request up.
var ErrNoRunningCoordinator = errors.New("no running coordinator answered; is 'openscale coordinator run' running on this state directory, and was it started by this version?")

// opsPoll is how often RequestOp looks for the reply.
const opsPoll = 200 * time.Millisecond

// RequestOp asks the coordinator running on dir for an operation and waits
// for its reply. Run it as the coordinator's user or as root.
func RequestOp(ctx context.Context, dir string, op string, duration time.Duration, timeout time.Duration) (OpsReply, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return OpsReply{}, err
	}
	req := OpsRequest{Schema: opsSchema, ID: hex.EncodeToString(raw[:]), Op: op, DurationS: int(duration / time.Second)}
	data, err := json.Marshal(req)
	if err != nil {
		return OpsReply{}, err
	}
	if _, err := ParseOpsRequest(data); err != nil {
		return OpsReply{}, err
	}
	path := filepath.Join(dir, OpsRequestFile)
	if err := securefile.Replace(path, data); err != nil {
		return OpsReply{}, err
	}
	// Root writes the request, the coordinator's user reads it; the state
	// directory itself stays 0700.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o644) //nolint:gosec // inside the 0700 state directory
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(opsPoll)
	defer ticker.Stop()
	replyPath := filepath.Join(dir, OpsReplyFile)
	for {
		select {
		case <-ctx.Done():
			_ = os.Remove(path)
			return OpsReply{}, ErrNoRunningCoordinator
		case <-ticker.C:
		}
		data, err := securefile.ReadLimited(replyPath, maxOpsFile)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return OpsReply{}, err
		}
		var reply OpsReply
		if err := decodeOps(data, &reply); err != nil {
			return OpsReply{}, fmt.Errorf("operation reply: %w", err)
		}
		if reply.ID != req.ID {
			continue // an older reply
		}
		_ = os.Remove(replyPath)
		if reply.Error != "" {
			return reply, errors.New(reply.Error)
		}
		return reply, nil
	}
}
