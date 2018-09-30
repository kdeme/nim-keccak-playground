template ptrToArray*[T](p:pointer):auto =
  type A{.unchecked.} = array[0..24,T]
  cast[ptr A](p)

template rol64(a, offset: untyped): untyped =
  (a shl offset) xor (a shr (64 - offset))

template i(x, y: untyped): untyped =
  (x + 5 * y)

template readLane(x, y: untyped): untyped =
  stateArray[i(x, y)]

template writeLane(x, y, lane: untyped): untyped =
  stateArray[i(x, y)] = lane

template xorLane(x, y, lane: untyped): untyped =
  stateArray[i(x, y)] = stateArray[i(x, y)] xor lane

proc LFSR86540(LFSR: ptr uint8): bool =
  result = (LFSR[] and 0x01) != 0

  if ((LFSR[] and 0x80) != 0):
    LFSR[] = (LFSR[] shl 1) xor 0x71
  else:
    LFSR[] = LFSR[] shl 1

proc keccakPermute(state: pointer) =
  var stateArray = ptrToArray[uint64](state)
  var LFSRstate: uint8 = 0x01

  for round in 0..23:
    block: # θ step
      var C: array[5, uint64]
      var D: uint64

      for x in 0..4:
        C[x] = readLane(x, 0) xor readLane(x, 1) xor readLane(x, 2) xor
               readLane(x, 3) xor readLane(x, 4)
      for x in 0..4:
        D = C[(x + 4) mod 5] xor rol64(C[(x + 1) mod 5], 1)
        for y in 0..4:
          xorLane(x, y, D)

    block: # ρ and π steps
      var current, temp: uint64
      var x: int = 1
      var y: int = 0

      current = readLane(x, y)
      for t in 0..23:
        var r: int = int((t + 1) * (t + 2) / 2) mod 64
        var Y: int = (2 * x + 3 * y) mod 5
        x = y
        y = Y
        temp = readLane(x, y)
        writeLane(x, y, rol64(current, r))
        current = temp

    block: # χ step
      var temp: array[5, uint64]
      for y in 0..4:
        for x in 0..4:
          temp[x] = readLane(x, y)
        for x in 0..4:
          writeLane(x, y, temp[x] xor
                    ((not temp[(x + 1) mod 5]) and temp[(x + 2) mod 5]))

    block: # ι step
      for j in 0..6:
        var bitPosition: uint =  (1'u shl j) - 1
        if(LFSR86540(addr(LFSRstate))):
          xorLane(0, 0, 1'u64 shl bitPosition)


proc keccak(rate: int, capacity: int,
             input: openArray[byte],
             inputLen: int,
             output: var openArray[byte],
             outputLen: int,
             delimitedSuffix: byte) =
  var state: array[200, byte]
  var stateP = addr(state)
  var rateInBytes = int(rate / 8)
  var blockSize = 0
  var offset = 0
  var inputByteLen = inputLen
  var outputByteLen = outputLen

  if (((rate + capacity) != 1600) or ((rate mod 8) != 0)):
    return

  while(inputByteLen > 0):
    blockSize = min(inputByteLen, rateInBytes);
    for i in 0..<blockSize:
      state[i] = state[i] xor input[i + offset]

    offset += blockSize
    inputByteLen -= blockSize

    if (blockSize == rateInBytes):
      keccakPermute(stateP)
      blocksize = 0;

  state[blockSize] = state[blockSize] xor delimitedSuffix;
  if (((delimitedSuffix and 0x80) != 0) and (blockSize == (rateInBytes-1))):
    keccakPermute(stateP)

  state[rateInBytes-1] = state[rateInBytes-1] xor 0x80
  keccakPermute(stateP)

  offset = 0
  while(outputByteLen > 0):
    blockSize = min(outputByteLen, rateInBytes);
    # change to use copyMem..?
    for i in 0..<blockSize:
      output[i + offset] = state[i]

    offset += blockSize
    outputByteLen -= blockSize

    if (outputByteLen > 0):
      keccakPermute(stateP)

template keccak224*(input, inputByteLen, output: untyped) =
  keccak(1152, 448, input, inputByteLen, output, int(224/8), 0x01)

template keccak256*(input,inputByteLen,  output: untyped) =
  keccak(1088, 512, input, inputByteLen, output, int(256/8), 0x01)

template keccak384*(input, inputByteLen, output: untyped) =
  keccak(832, 768, input, inputByteLen, output, int(384/8), 0x01)

template keccak512*(input, inputByteLen, output: untyped) =
  keccak(576, 1024, input, inputByteLen, output, int(512/8), 0x01)

template shake128*(input, inputByteLen, output, outputByteLen: untyped) =
  keccak(1344, 256, input, inputByteLen, output, outputByteLen, 0x1F )

template shake256*(input, inputByteLen, output, outputByteLen: untyped) =
  keccak(1088, 512, input, inputByteLen, output, outputByteLen, 0x1F)

template sha3_224*(input, inputByteLen, output: untyped) =
  keccak(1152, 448, input, inputByteLen, output, int(224/8), 0x06)

template sha3_256*(input, inputByteLen, output: untyped) =
  keccak(1088, 512, input, inputByteLen, output, int(256/8), 0x06)

template sha3_384*(input, inputByteLen, output: untyped) =
  keccak(832, 768, input, inputByteLen, output, int(384/8), 0x06)

template sha3_512*(input, inputByteLen, output: untyped) =
  keccak(576, 1024, input, inputByteLen, output, int(512/8), 0x06)
