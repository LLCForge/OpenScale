//go:build linux

package rdesk

import "image"

// pipewireFrames reads the newest frame of each portal stream.
type pipewireFrames interface {
	// frame copies the newest frame of stream i into buf (grown as
	// needed) as opaque RGBA rows and returns it with its size; a zero
	// size means no frame has arrived yet.
	frame(i int, buf []byte) ([]byte, image.Point, error)
	// size is the newest frame's size of stream i (zero before the
	// first frame).
	size(i int) image.Point
	close()
}
