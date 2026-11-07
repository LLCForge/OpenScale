package client

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/openscale/openscale/internal/webhook"
)

// Webhook receivers (F-189, ADR-0108). "openscale webhook run" signs every
// delivery with the shared secret printed by "openscale webhook init".

// Webhook headers and payload.
const (
	WebhookSignatureHeader = webhook.HeaderSignature
	WebhookEventHeader     = webhook.HeaderEvent
	WebhookDeliveryHeader  = webhook.HeaderDelivery
)

// WebhookPayload is the JSON body of a delivery.
type WebhookPayload = webhook.Payload

// VerifyWebhook checks the X-OpenScale-Signature header of a delivery
// against the hex secret, accepting a timestamp within five minutes of
// now. Call it on the raw body before parsing it.
func VerifyWebhook(secretHex, signature string, body []byte, now time.Time) error {
	secret, err := hex.DecodeString(secretHex)
	if err != nil || len(secret) < 16 {
		return errors.New("openscale: webhook secret is malformed")
	}
	return webhook.Verify(secret, signature, body, now, webhook.Tolerance)
}
