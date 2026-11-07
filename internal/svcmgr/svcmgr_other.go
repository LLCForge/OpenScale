//go:build !linux && !windows && !darwin

package svcmgr

import "context"

// Install is not supported here.
func Install(context.Context, Options) (Result, error) { return Result{}, ErrUnsupported }

// Start is not supported here.
func Start(context.Context, Role) error { return ErrUnsupported }

// Stop is not supported here.
func Stop(context.Context, Role) error { return ErrUnsupported }

// Restart is not supported here.
func Restart(context.Context, Role) error { return ErrUnsupported }

// Get is not supported here.
func Get(context.Context, Role) (Status, error) { return Status{}, ErrUnsupported }

// Uninstall is not supported here.
func Uninstall(context.Context, Role) ([]string, error) { return nil, ErrUnsupported }
