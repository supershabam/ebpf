package ebpf

const (
	bpfProgLoad       = 5
	bpfMapCreate      = 0
	bpfProgTypeKProbe = 2
)

type BPFProgType uint32

const (
	SocketFilter BPFProgType = 1
	KProbe       BPFProgType = 2
)