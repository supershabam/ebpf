package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/paypal/gatt/linux/gioctl"
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
	syscallBPF           = 321 // /usr/src/linux-headers-4.4.0-81-generic/arch/x86/include/generated/uapi/asm/unistd_64.h
	syscallPerfEventOpen = 298 // /usr/src/linux-headers-4.4.0-81-generic/arch/x86/include/generated/uapi/asm/unistd_64.h:#define __NR_perf_event_open 298
	bpfProgLoad          = 5
	bpfMapCreate         = 0
	bpfProgTypeKProbe    = 2
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
	ProgType      BPFProgType
	Instns        []BPFInst
	License       string
	LogLevel      uint32
	LogBufSize    uint32
	Log           []byte
	KernelVersion uint32
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
	binary.Write(buf, binary.LittleEndian, uint32(plc.KernelVersion))
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

func bpfProg(config *bpfProgLoadConfig) (fd uintptr, errno syscall.Errno) {
	ptr, n, gc := config.Ptr()
	use(gc)
	fd, _, errno = syscall.Syscall(syscallBPF, uintptr(int(bpfProgLoad)), uintptr(ptr), uintptr(n))
	return
}

type PerfEventAttr struct {
	Type         uint32
	Config       uint64
	SamplePeriod uint64
	SampleType   uint64
	WakeupEvents uint32
}

func (pea *PerfEventAttr) Bytes() []byte {
	// 14 * 64bits = 112 bytes
	var size = uint32(112) // TODO set size
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, pea.Type)
	binary.Write(buf, binary.LittleEndian, size)
	binary.Write(buf, binary.LittleEndian, pea.Config)
	binary.Write(buf, binary.LittleEndian, pea.SamplePeriod)
	binary.Write(buf, binary.LittleEndian, pea.SampleType)
	binary.Write(buf, binary.LittleEndian, uint64(0)) // read_format
	binary.Write(buf, binary.LittleEndian, uint64(0)) // bit vector
	binary.Write(buf, binary.LittleEndian, pea.WakeupEvents)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // bp_type
	binary.Write(buf, binary.LittleEndian, uint64(0)) //	64 bp_addr
	binary.Write(buf, binary.LittleEndian, uint64(0)) //	64 bp_len
	binary.Write(buf, binary.LittleEndian, uint64(0)) //	64 branch_sample_type
	binary.Write(buf, binary.LittleEndian, uint64(0)) //	64 sample_regs_user
	binary.Write(buf, binary.LittleEndian, uint32(0)) //	32 sample_stack_user
	binary.Write(buf, binary.LittleEndian, uint32(0)) //	32 clockid
	binary.Write(buf, binary.LittleEndian, uint64(0)) //	64 sample_regs_intr
	binary.Write(buf, binary.LittleEndian, uint32(0)) //	32 aux_watermark
	binary.Write(buf, binary.LittleEndian, uint32(0)) //	32	__reserved_2;	/* align to __u64 */
	b := buf.Bytes()
	if len(b) != int(size) {
		panic("length of buffer expected to match size")
	}
	return b
}

// struct perf_event_attr {

// 	/*
// 	 * Major type: hardware/software/tracepoint/etc.
// 	 */
// 	__u32			type; size = 4

// 	/*
// 	 * Size of the attr structure, for fwd/bwd compat.
// 	 */
// 	__u32			size; size = 8

// 	/*
// 	 * Type specific configuration information.
// 	 */
// 	__u64			config; size = 16

// 	union { size = 24
// 		__u64		sample_period;
// 		__u64		sample_freq;
// 	};

// 	__u64			sample_type; size = 32
// 	__u64			read_format; size = 40

// 	__u64			disabled       :  1, /* off by default        */ size = 48
// 				inherit	       :  1, /* children inherit it   */
// 				pinned	       :  1, /* must always be on PMU */
// 				exclusive      :  1, /* only group on PMU     */
// 				exclude_user   :  1, /* don't count user      */
// 				exclude_kernel :  1, /* ditto kernel          */
// 				exclude_hv     :  1, /* ditto hypervisor      */
// 				exclude_idle   :  1, /* don't count when idle */
// 				mmap           :  1, /* include mmap data     */
// 				comm	       :  1, /* include comm data     */
// 				freq           :  1, /* use freq, not period  */
// 				inherit_stat   :  1, /* per task counts       */
// 				enable_on_exec :  1, /* next exec enables     */
// 				task           :  1, /* trace fork/exit       */
// 				watermark      :  1, /* wakeup_watermark      */
// 				/*
// 				 * precise_ip:
// 				 *
// 				 *  0 - SAMPLE_IP can have arbitrary skid
// 				 *  1 - SAMPLE_IP must have constant skid
// 				 *  2 - SAMPLE_IP requested to have 0 skid
// 				 *  3 - SAMPLE_IP must have 0 skid
// 				 *
// 				 *  See also PERF_RECORD_MISC_EXACT_IP
// 				 */
// 				precise_ip     :  2, /* skid constraint       */
// 				mmap_data      :  1, /* non-exec mmap data    */
// 				sample_id_all  :  1, /* sample_type all events */

// 				exclude_host   :  1, /* don't count in host   */
// 				exclude_guest  :  1, /* don't count in guest  */

// 				exclude_callchain_kernel : 1, /* exclude kernel callchains */
// 				exclude_callchain_user   : 1, /* exclude user callchains */
// 				mmap2          :  1, /* include mmap with inode data     */
// 				comm_exec      :  1, /* flag comm events that are due to an exec */
// 				use_clockid    :  1, /* use @clockid for time fields */
// 				context_switch :  1, /* context switch data */
// 				__reserved_1   : 37;

// 	union { size = 52
// 		__u32		wakeup_events;	  /* wakeup every n events */
// 		__u32		wakeup_watermark; /* bytes before wakeup   */
// 	};

// 	__u32			bp_type;
// 	union {
// 		__u64		bp_addr;
// 		__u64		config1; /* extension of config */
// 	};
// 	union {
// 		__u64		bp_len;
// 		__u64		config2; /* extension of config1 */
// 	};
// 	__u64	branch_sample_type; /* enum perf_branch_sample_type */

// 	/*
// 	 * Defines set of user regs to dump on samples.
// 	 * See asm/perf_regs.h for details.
// 	 */
// 	__u64	sample_regs_user;

// 	/*
// 	 * Defines size of the user stack to dump on samples.
// 	 */
// 	__u32	sample_stack_user;

// 	__s32	clockid;
// 	/*
// 	 * Defines set of regs to dump for each sample
// 	 * state captured on:
// 	 *  - precise = 0: PMU interrupt
// 	 *  - precise > 0: sampled instruction
// 	 *
// 	 * See asm/perf_regs.h for details.
// 	 */
// 	__u64	sample_regs_intr;

// 	/*
// 	 * Wakeup watermark for AUX area
// 	 */
// 	__u32	aux_watermark;
// 	__u32	__reserved_2;	/* align to __u64 */
// };

const (
	perfTypeTracepoint  uint32 = 2
	perfSampleCallchain uint64 = 1 << 5
	perfSampleRaw       uint64 = 1 << 10
	perfFlagFDCloexec   uint64 = 1 << 3 /* O_CLOEXEC */
)

func main() {
	config := &bpfProgLoadConfig{
		ProgType: KProbe,
		Instns: []BPFInst{
			// 0x0118, // lddw dst, imm
			0xb7, // BPF_MOV64_IMM(BPF_REG_0, 0)
			0x95, // return r0
		},
		License:       "GPL",
		LogLevel:      5,
		LogBufSize:    256,
		KernelVersion: 0x40400,
	}
	progFD, errno := bpfProg(config)
	if errno != 0 {
		spew.Dump(config.Log)
		panic("bpf prog non-zero errno: " + fmt.Sprintf("%d", errno))
	}

	ke, err := os.OpenFile("/sys/kernel/debug/tracing/kprobe_events", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		panic(err)
	}
	_, err = ke.WriteString("p:emitio/tcp_v4_connect_fn tcp_v4_connect")
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadFile("/sys/kernel/debug/tracing/events/emitio/tcp_v4_connect_fn/id")
	if err != nil {
		panic(err)
	}
	id, err := strconv.ParseUint(strings.Split(string(b), "\n")[0], 10, 64)
	if err != nil {
		panic(err)
	}
	fmt.Printf("id: %d\n", id)
	pea := &PerfEventAttr{
		Type:         perfTypeTracepoint,
		Config:       id, // Set with ID from perf
		SamplePeriod: 1,
		SampleType:   perfSampleRaw | perfSampleCallchain,
		WakeupEvents: 1,
	}
	b = pea.Bytes()
	pid := 0
	cpu := -1
	group := -1
	r0, _, e1 := syscall.Syscall6(syscallPerfEventOpen, uintptr(unsafe.Pointer(&b[0])), uintptr(pid), uintptr(cpu), uintptr(group), uintptr(perfFlagFDCloexec), uintptr(0))
	fmt.Printf("r0: %d\ne1: %d\n", r0, e1)
	// mmap, err := gommap.Map(file.Fd(), gommap.PROT_READ,
	//                             gommap.MAP_PRIVATE)
	//     if err == nil {
	//         end := bytes.Index(mmap, []byte("\n"))
	//         println(string([]byte(mmap[:end])))
	//     }
	// #define PERF_EVENT_IOC_SET_BPF		_IOW('$', 8, __u32)
	op := gioctl.IoW('$', 8, 32)
	err = gioctl.Ioctl(r0, op, progFD)
	if err != nil {
		panic(err)
	}
}
