import  strformat, tables, json, strutils, sequtils, hashes, net, asyncdispatch, asyncnet, os, parseutils, deques, options

# Aqui o * indica que o campo é publico
type ForwardOptions = object
  listenAddr*: string
  listenPort*: Port
  toAddr*: string
  toPort*: Port
  logFile*: string   # caminho opcional para gravar logs (se vazio, apenas stdout)


type Forwarder = object of RootObj
  options*: ForwardOptions


proc newForwarder(opts: ForwardOptions): ref Forwarder =
  result = new(Forwarder)
  result.options = opts


# helper: append to a file (fallback that uses readFile/writeFile so we don't call a missing symbol)
proc appendFileSafe(path: string, data: string) =
  try:
    if existsFile(path):
      let prev = readFile(path)
      writeFile(path, prev & data)
    else:
      writeFile(path, data)
  except OSError:
    raise


proc detectRequestType(buf: string): string =
  let s = buf.strip()
  if s.len == 0: return "unknown"
  # splitWhitespace retorna seq[string]; guardar e verificar comprimento
  let toks = s.splitWhitespace()
  if toks.len == 0: return "unknown"
  let first = toks[0].toUpperAscii()
  if first in @["GET","POST","HEAD","PUT","DELETE","OPTIONS","PATCH","CONNECT","TRACE"]:
    return "http"
  # basic TLS ClientHello detection: first byte 0x16 (handshake record)
  if buf.len > 0 and buf[0] == '\x16':
    return "tls"
  return "unknown"



proc copyLoop(src: AsyncSocket, dst: AsyncSocket) {.async.} =
  var data: string
  try:
    while true:
      data = await src.recv(8192)
      if data.len == 0:
        break
      await dst.send(data)
  except OSError:
    discard
  # caller is responsible for closing sockets

proc processClient(this: ref Forwarder, client: AsyncSocket) {.async.} =
  let remote = newAsyncSocket(buffered=false)
  # try to connect to target
  try:
    await remote.connect(this.options.toAddr, this.options.toPort)
  except OSError as e:
    echo fmt"Failed to connect to remote {this.options.toAddr}:{this.options.toPort} -- {e.msg}"
    try: client.close() except: discard
    return

  # read a first chunk from client to detect request type (non-blocking await)
  var firstChunk = ""
  try:
    firstChunk = await client.recv(4096)
  except OSError:
    firstChunk = ""

  let reqType = detectRequestType(firstChunk)

  # gather peer info if available (best-effort)
  var clientIp: string = ""
  var clientPort: string = ""
  try:
    clientIp = $client.getPeerAddr()
    #clientPort = $client.getPeerPort()
  except:
    discard

  # emit JSON-line to stdout
  let logJson = %*{
    "client_ip": clientIp,
    "client_port": clientPort,
    "target": fmt"{this.options.toAddr}:{this.options.toPort}",
    "request_type": reqType
  }
  let line = $logJson
  echo line # JSON line to stdout

# append JSON-line to logfile if configured
  if this.options.logFile.len > 0:
    try:
      appendFileSafe(this.options.logFile, line & "\n")
    except OSError as e:
      # falha em gravar não interrompe o proxy, apenas reporta em stdout
      echo fmt"Failed writing log to {this.options.logFile}: {e.msg}"

  # forward first chunk to remote (if any)
  if firstChunk.len > 0:
    try:
      await remote.send(firstChunk)
    except OSError:
      try: client.close() except: discard
      try: remote.close() except: discard
      return

  # start bidirectional forwarding: spawn one side and await the other
  asyncCheck copyLoop(client, remote)
  await copyLoop(remote, client)

  # close sockets gracefully
  try: client.close() except: discard
  try: remote.close() except: discard


proc serve(this: ref Forwarder) {.async.} =
  var server = newAsyncSocket(buffered=false)
  server.setSockOpt(OptReuseAddr, true)
  server.bindAddr(this.options.listenPort, this.options.listenAddr)
  echo fmt"Started tcp server... {this.options.listenAddr}:{this.options.listenPort} "
  server.listen()
  
  while true:
    let client = await server.accept()
    echo "..Got connection "

    asyncCheck this.processClient(client)
    # await means execute that async action and block the execution until you get a result.
    # asyncCheck means execute async action and don't block a suitable name might be discard or discardAsync



when isMainModule:
  # parse command line args
  let opts = ForwardOptions(listenAddr:"127.0.0.1", listenPort:11000.Port, toAddr:"127.0.0.1", toPort:8000.Port)
  var f = newForwarder(opts)
  asyncCheck f.serve()
  runForever()










