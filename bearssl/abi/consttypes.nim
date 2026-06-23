type
  ConstPointer* {.importc: "const void *".} = pointer
  ConstPtrByte* {.importc: "const unsigned char *".} = pointer
  ConstCstring* {.importc: "const char *".} = cstring
