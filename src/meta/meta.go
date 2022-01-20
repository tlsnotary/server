// contains various structures with circuit metadata

package meta

// Gate represents a circuit's gate
type Gate struct {
	// Id is gate number, Ids start with 0 and increment
	Id uint32
	// Operation is 0 for XOR, 1 for AND, 2 for INV
	Operation uint8
	// InputWires is the sequence number of the input wires. Each gate has 1
	// (for INV) or 2 (for XOR or AND) wires going into it
	InputWires []uint32
	// OutputWire is the sequence number of the output wire of this gate.
	OutputWire uint32
}

// Circuit contains read only information for each circuit and used both by
// the garbler and the evaluator
type Circuit struct {
	// WireCount is total amount of wires in the circuit
	WireCount int
	// NotaryInputSize is the count of bits in notary's input
	NotaryInputSize int
	// ClientInputSize is the count of bits in client's input
	ClientInputSize int
	// OutputSize is the count of bits in the circuit's output
	OutputSize int
	// AndGateCount the count of AND gates in the circuit
	AndGateCount int
	// Gates is an array of all gates of the circuit
	Gates []Gate
	// The output of a circuit is actually multiple concatenated values. We need
	// to know how many bits each output value has in order to parse the output
	// of all the members of this struct, OutputsSizes is the only one which
	// cannot be obtained by parsing the raw circuit. We input this value manually
	OutputsSizes []int
}

// GetOutputSizes takes the number of a circuit and returns a slice with
// bit lengths for each of the circuit's output variable.
func GetOutputSizes(idx int) []int {
	outputSizes := [][]int{
		nil,
		[]int{256, 256},
		[]int{256, 256},
		[]int{128, 128, 32, 32},
		[]int{128, 128, 128},
		[]int{128, 128, 128, 96},
		[]int{128},
		[]int{128}}
	return outputSizes[idx]
}
