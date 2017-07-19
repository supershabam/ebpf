package ebpf



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