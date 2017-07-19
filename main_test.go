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
