package main_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"syscall"
	"testing"
	"unsafe"
)

// http://man7.org/linux/man-pages/man2/bpf.2.html
// http://elixir.free-electrons.com/linux/latest/source/include/linux/syscalls.h#L889
// https://ferrisellis.com/posts/ebpf_syscall_and_maps/#the-linux-bpf-syscall
// http://elixir.free-electrons.com/linux/latest/source/include/uapi/linux/bpf.h#L73
// https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
// http://www.virtsync.com/c-error-codes-include-errno
// https://golang.org/src/syscall/syscall.go
// https://golang.org/src/syscall/zsyscall_linux_amd64.go?s=12082:12134#L491

// Single-word zero for use when we need a valid pointer to 0 bytes.
// See mksyscall.pl.
var _zero uintptr

const (
	syscallBPF        = 321 // /usr/src/linux-headers-4.4.0-81-generic/arch/x86/include/generated/uapi/asm/unistd_64.h
	bpfProgLoad       = 5
	bpfMapCreate      = 0
	bpfProgTypeKProbe = 2
)

//    struct {    /* Used by BPF_MAP_CREATE */
//        __u32         map_type;
//        __u32         key_size;    /* size of key in bytes */
//        __u32         value_size;  /* size of value in bytes */
//        __u32         max_entries; /* maximum number of entries
//                                      in a map */
//    };

type bpfMapCreateConfig struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
}

func (mc *bpfMapCreateConfig) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, mc.mapType)
	binary.Write(buf, binary.LittleEndian, mc.keySize)
	binary.Write(buf, binary.LittleEndian, mc.valueSize)
	binary.Write(buf, binary.LittleEndian, mc.maxEntries)
	return buf.Bytes()
}

// struct { /* anonymous struct used by BPF_PROG_LOAD command */
// 	__u32		prog_type;	/* one of enum bpf_prog_type */
// 	__u32		insn_cnt;
// 	__aligned_u64	insns;
// 	__aligned_u64	license;
// 	__u32		log_level;	/* verbosity level of verifier */
// 	__u32		log_size;	/* size of user buffer */
// 	__aligned_u64	log_buf;	/* user supplied buffer */
// 	__u32		kern_version;	/* checked when prog_type=kprobe */
// 	__u32		prog_flags;
// }

type BPFProgType uint32

const (
	SockerFilter BPFProgType = 1
	KProbe       BPFProgType = 2
)

type BPFInst uint64

type bpfProgLoadConfig struct {
	ProgType   BPFProgType
	Instns     []BPFInst
	License    string
	LogLevel   uint32
	LogBufSize uint32
	Log        []byte
}

// Ptr serializes the config into a usable ptr to pass to syscall. The returned slice of
// byte slices must be referenced by the caller to avoid garbage collection on the underlaying
// pointer.
func (plc *bpfProgLoadConfig) Ptr() (unsafe.Pointer, int, [][]byte) {
	gc := make([][]byte, 0)
	insns := new(bytes.Buffer)
	for _, insn := range plc.Instns {
		binary.Write(insns, binary.LittleEndian, insn)
	}
	insnsBytes := insns.Bytes()
	gc = append(gc, insnsBytes)
	i, _ := strconv.ParseInt(fmt.Sprintf("%p", insnsBytes), 0, 64)
	insnsBytesAddr := uint64(i)

	license := new(bytes.Buffer)
	binary.Write(license, binary.LittleEndian, bytes.NewBufferString(plc.License).Bytes())
	binary.Write(license, binary.LittleEndian, uint8(0))
	licenseBytes := license.Bytes()
	gc = append(gc, licenseBytes)
	i, _ = strconv.ParseInt(fmt.Sprintf("%p", licenseBytes), 0, 64)
	licenseBytesAddr := uint64(i)

	logBuf := make([]byte, plc.LogBufSize)
	gc = append(gc, logBuf)
	i, _ = strconv.ParseInt(fmt.Sprintf("%p", logBuf), 0, 64)
	logBufAddr := uint64(i)
	plc.Log = logBuf

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(plc.ProgType))
	binary.Write(buf, binary.LittleEndian, uint32(len(plc.Instns)))
	binary.Write(buf, binary.LittleEndian, insnsBytesAddr)
	binary.Write(buf, binary.LittleEndian, licenseBytesAddr)
	binary.Write(buf, binary.LittleEndian, plc.LogLevel)
	binary.Write(buf, binary.LittleEndian, plc.LogBufSize)
	binary.Write(buf, binary.LittleEndian, logBufAddr)
	// LINUX_VERSION_CODE
	// # error Example: for 4.2 kernel, put 'clang-opt="-DLINUX_VERSION_CODE=0x40200" into llvm section of ~/.perfconfig'
	binary.Write(buf, binary.LittleEndian, uint32(0x040400))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	bufBytes := buf.Bytes()
	return unsafe.Pointer(&bufBytes[0]), len(bufBytes), gc
}

func bpfMap(config *bpfMapCreateConfig) {
	buf := config.Bytes()
	bufPtr := unsafe.Pointer(&buf[0])
	r0, _, e1 := syscall.Syscall(syscallBPF, uintptr(int(bpfMapCreate)), uintptr(bufPtr), uintptr(len(buf)))
	fmt.Printf("r0: %d\ne1: %d\n", r0, e1)
}

func use(i interface{}) {
	return
}

func bpfProg(config *bpfProgLoadConfig) {
	ptr, n, gc := config.Ptr()
	use(gc)
	r0, _, e1 := syscall.Syscall(syscallBPF, uintptr(int(bpfProgLoad)), uintptr(ptr), uintptr(n))
	fmt.Printf("r0: %d\ne1: %d\n", r0, e1)
}

func TestBPF(t *testing.T) {
	// bpfMap(&bpfMapCreateConfig{
	// 	mapType:    1,
	// 	keySize:    8,
	// 	valueSize:  8,
	// 	maxEntries: 32,
	// })

	config := &bpfProgLoadConfig{
		ProgType: SockerFilter,
		Instns: []BPFInst{
			0xb7, // BPF_MOV64_IMM(BPF_REG_0, 0)
			0x95, // return r0
		},
		License:    "GPL",
		LogLevel:   1,
		LogBufSize: 255,
	}
	bpfProg(config)
	fmt.Printf("log: %s\n", config.Log)

	// bpfProg(&bpfAttr{
	// 	progType:    bpfProgTypeKProbe,
	// 	insns:       []uint64{0x95},
	// 	license:     "GPL",
	// 	logLevel:    1,
	// 	log:         make([]uint64, 256),
	// 	kernVersion: 0x0a0b0c0d,
	// 	flags:       0,
	// })
	// time.Sleep(time.Minute * 5)
}
