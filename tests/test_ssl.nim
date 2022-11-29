import
  unittest2,
  std/strutils,
  std/strformat,
  std/net,
  std/nativesockets,
  ../bearssl,
  ../bearssl/certs/cacert

suite "SSL":
  test "client":
    let
      hostname = "httpbin.org"
      port = 443.Port
    var
      sc: SslClientContext
      xc: X509MinimalContext
      io: SslioContext
      iobuffer: array[SSL_BUFSIZE_BIDI, char]

    var socket = net.dial(hostname, port, buffered = true)
    defer: socket.close()

    proc lowRead(readContext: pointer; data: ptr byte; len: uint): cint {.cdecl.} =
      var sock = cast[Socket](readContext)
      result = sock.recv(cast[pointer](data), len.int).cint
      checkpoint &"lowRead {len} -> {result}"
      if result == 0:
        checkpoint "Error reading"
        return -1
    
    proc lowWrite(writeContext: pointer; data: ptr byte; len: uint): cint {.cdecl.} =
      var sock = cast[Socket](writeContext)
      result = sock.send(cast[pointer](data), len.int).cint
      checkpoint &"lowWrite {len} -> {result}"
      if result == 0:
        checkpoint "Error writing"
        return -1

    sslClientInitFull(sc, xc.addr, MozillaTrustAnchors[0].addr, MozillaTrustAnchorsCount)
    sslEngineSetBuffer(sc.eng, iobuffer.addr, SSL_BUFSIZE_BIDI, 1)
    assert sslClientReset(sc, hostname, 0) == 1
    sslioInit(io, sc.eng.addr, lowRead, socket[].addr, lowWrite, socket[].addr)
    
    checkpoint "sslInit finished"

    # Send request
    block:
      # for 
      # let payload = "Foo"
      let payload = [
        "GET /status/200 HTTP/1.0",
        &"Host: {hostname}",
        "User-Agent: nimbearssl/0.1.5",
        "Accept: */*",
        "",
        "",
      ].join("\r\n")
      var buf = payload.cstring
      check: sslioWriteAll(io, buf.addr, buf.len.uint) == 0
      check: sslioFlush(io) == 0

    # Read response
    block:
      const READ_BUFFER_LEN = 512
      var response: string
      var buf: array[READ_BUFFER_LEN, char]
      while true:
        var n = sslioRead(io, buf[0].addr, READ_BUFFER_LEN)
        if n <= 0:
          break
        for i in 0..<n:
          response.add buf[i]
      checkpoint response
      check: "200 OK" in response
    
    socket.close()
    
    check: sslEngineCurrentState(sc.eng) == SSL_CLOSED
    check: sslEngineLastError(sc.eng) == 0
