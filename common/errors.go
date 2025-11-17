package common

import "errors"

var (
	ErrInvalidChannel       = errors.New("Connect: Channel must be ChanSign or ChanMgmt")
	ErrNoDevices            = errors.New("no devices with VID/PID")
	ErrDeviceNotFound       = errors.New("device with requested serial not found")
	ErrUSBResetFailed       = errors.New("usb: reset failed")
	ErrGadgetNotReady       = errors.New("gadget not ready: no vendor-specific (FFS) interface exposed")
	ErrNoManagementIface    = errors.New("no management interface present")
	ErrVendorProbeFailed    = errors.New("vendor probe failed")
	ErrInterfaceNotReady    = errors.New("interface not ready")
	ErrInterfaceClaimFailed = errors.New("claim interface failed")
	ErrSignInterfaceBusy    = errors.New("Unable to connect to sign interface of the device, device is busy")
	ErrMgmtInterfaceBusy    = errors.New("Unable to connect to management interface of the device, device is busy")
)
