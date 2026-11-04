package hostsfile

// Version identifies the state of a host file. The daemon compares two
// Versions: they must be equal while the file does not change, and
// different after a change. The zero Version is a file that does not
// exist. The reader decides which fields it fills; hostsfs uses the
// modification time and the size.
type Version struct {
	Exists  bool
	ModNano int64
	Size    int64
}
