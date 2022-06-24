import
  "."/[csources]

{.used.}

const
  bearCodecPath = bearSrcPath & "codec/"

{.compile: bearCodecPath & "ccopy.c".}
{.compile: bearCodecPath & "dec16be.c".}
{.compile: bearCodecPath & "dec16le.c".}
{.compile: bearCodecPath & "dec32be.c".}
{.compile: bearCodecPath & "dec32le.c".}
{.compile: bearCodecPath & "dec64be.c".}
{.compile: bearCodecPath & "dec64le.c".}
{.compile: bearCodecPath & "enc16be.c".}
{.compile: bearCodecPath & "enc16le.c".}
{.compile: bearCodecPath & "enc32be.c".}
{.compile: bearCodecPath & "enc32le.c".}
{.compile: bearCodecPath & "enc64be.c".}
{.compile: bearCodecPath & "enc64le.c".}
