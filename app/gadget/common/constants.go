package common

var (
	FfsInstanceRoot = "/dev/ffs/tezsign"

	EnabledSock = "/tmp/tezsign.enabled"
	ReadySock   = "/tmp/tezsign.ready"

	AppMountPoint = "/app"

	ImageVersionFile   = AppMountPoint + "/.image-version"
	ImageBuildDateFile = AppMountPoint + "/.image-date"
)
