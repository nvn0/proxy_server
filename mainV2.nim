import  strformat, tables, json, strutils, sequtils, hashes, net, asyncdispatch, asyncnet, os, parseutils, deques, options


# Funciona mais como um proxy "normal", funciona como proxy para o firefox

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
    if fileExists(path):
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


# helper: parse host[:port] string, retorna (host, Port)
proc parseHostPort(s: string, defPort: int): (string, Port) =
  var host = s.strip()
  var port = defPort
  if host.contains(':'):
    let parts = host.split(':')
    if parts.len >= 2:
      host = parts[0].strip()
      try:
        let p = parseInt(parts[1].strip())
        if p > 0: port = p
      except:
        discard
  return (host, Port(port))




# tenta extrair destino real de uma requisição HTTP/CONNECT; devolve (host, port)
proc extractTargetFromHttp(firstChunk: string, defaultHost: string, defaultPort: int): (string, Port) =
  let lines = firstChunk.splitLines()
  if lines.len == 0:
    return (defaultHost, Port(defaultPort))
  let reqLine = lines[0]
  let toks = reqLine.splitWhitespace()
  if toks.len < 2:
    return (defaultHost, Port(defaultPort))
  let verb = toks[0].toUpperAscii()
  let targetTok = toks[1]
  # CONNECT host:port
  if verb == "CONNECT":
    return parseHostPort(targetTok, defaultPort)
  # absolute URL in request line: http://host/... or https://host/...
  var after = targetTok
  if after.startsWith("http://"):
    after = after.substr(7)
  elif after.startsWith("https://"):
    after = after.substr(8)
  if after.len > 0 and not (after[0] in [' ', '\t', '\r', '\n']):
    let hostPart = after.split('/')[0]
    if hostPart.len > 0:
      return parseHostPort(hostPart, defaultPort)
  # fallback: procurar header Host:
  for i in 1 ..< lines.len:
    let ln = lines[i]
    if ln.len > 5 and ln[0..4].toLowerAscii() == "host:":
      let hv = ln.split(':', 2)[1].strip()
      if hv.len > 0:
        return parseHostPort(hv, defaultPort)
  # fallback geral
  return (defaultHost, Port(defaultPort))



# Modificação em processClient: antes de conectar ao remote, tentar extrair destino real se HTTP
proc processClient(this: ref Forwarder, client: AsyncSocket) {.async.} =
  var targetHost = this.options.toAddr
  var targetPort: Port = this.options.toPort

  # ler um primeiro bloco do cliente para detectar tipo e (se for HTTP) destino real
  var firstChunk = ""
  try:
    firstChunk = await client.recv(4096)
  except OSError:
    firstChunk = ""

  let reqType = detectRequestType(firstChunk)

  var isConnect = false
  var origReqLine = ""
  var toks: seq[string] = @[]
  if reqType == "http":
    # extrai destino e guarda request line para detecção de CONNECT e reescrita
    let lines = firstChunk.splitLines()
    if lines.len > 0:
      origReqLine = lines[0]
      toks = origReqLine.splitWhitespace()
    if toks.len >= 1 and toks[0].toUpperAscii() == "CONNECT":
      isConnect = true


    let (h, p) = extractTargetFromHttp(firstChunk, this.options.toAddr, int(this.options.toPort))
    targetHost = h
    targetPort = p

  # agora tentar conectar ao destino determinado
  # DEBUG: mostrar destino e request original para diagnóstico
  echo fmt"DEBUG: will connect to {targetHost}:{targetPort} reqType={reqType} origReqLine={origReqLine}"
  if firstChunk.len > 0:
    let previewLen = if firstChunk.len < 200: firstChunk.len else: 200
    echo "DEBUG: firstChunk preview: " & firstChunk.substr(0, previewLen).replace("\r", "\\r").replace("\n", "\\n")


  # depois de decidir targetHost/targetPort, verificação de fallback:
  if targetHost.len == 0 or int(targetPort) == 0:
    echo "No target determined and no fallback configured — closing connection"
    try: client.close() except: discard
    return


  # agora tentar conectar ao destino determinado
  let remote = newAsyncSocket(buffered=false)
  try:
    await remote.connect(targetHost, targetPort)
  except OSError as e:
    echo fmt"Failed to connect to remote {targetHost}:{targetPort} -- {e.msg}"
    # detalhe adicional para diagnóstico
    echo fmt"DEBUG: firstChunk.len={firstChunk.len} origReqLine='{origReqLine}'"
    try: client.close() except: discard
    return

  # logging (regista o destino real)
  var clientIp = ""
  try: clientIp = $client.getPeerAddr() except: discard

  # extrair User-Agent (best-effort) a partir dos headers do firstChunk
  var userAgent = ""
  if firstChunk.len > 0:
    let hdrLines = firstChunk.splitLines()
    for i in 1 ..< hdrLines.len:
      let ln = hdrLines[i]
      if ln.len >= 11 and ln[0..10].toLowerAscii() == "user-agent:":
        let parts = ln.split(':', 2)
        if parts.len >= 2:
          userAgent = parts[1].strip()
        break

  let logJson = %*{
    "client_ip": clientIp,
    "target": fmt"{targetHost}:{targetPort}",
    "request_type": reqType,
    "user_agent": userAgent,
    "orig_req_line": origReqLine,
    "first_chunk_len": $firstChunk.len
  }
  let line = $logJson
  echo line


  if this.options.logFile.len > 0:
    try:
      appendFileSafe(this.options.logFile, line & "\n")
    except OSError as e:
      echo fmt"Failed writing log to {this.options.logFile}: {e.msg}"

  # Se for CONNECT: responder 200 ao cliente e iniciar túnel (não enviar CONNECT ao remoto)
  if isConnect:
    try:
      await client.send("HTTP/1.1 200 Connection established\r\n\r\n")
    except OSError:
      try: client.close() except: discard
      try: remote.close() except: discard
      return

    asyncCheck copyLoop(client, remote)
    await copyLoop(remote, client)

    try: client.close() except: discard
    try: remote.close() except: discard
    return

  # Se for HTTP e a primeira linha era uma URI absoluta, reescrever request-line para path antes de enviar
  if reqType == "http" and origReqLine.len > 0 and toks.len >= 2:
    var first = toks[0]
    var targetTok = toks[1]
    var newReqLine = origReqLine
    if targetTok.startsWith("http://") or targetTok.startsWith("https://"):
      var after = targetTok
      if after.startsWith("http://"): after = after.substr(7)
      elif after.startsWith("https://"): after = after.substr(8)
      var path = "/"
      let slashIdx = after.find('/')
      if slashIdx >= 0:
        path = after.substr(slashIdx)
      newReqLine = if toks.len >= 3: fmt"{first} {path} {toks[2]}" else: fmt"{first} {path}"
      # substituir a primeira linha dos headers por newReqLine
      var lines = firstChunk.splitLines()
      if lines.len > 0:
        lines[0] = newReqLine
        # reconstruir headers + resto (simples: junta com CRLF)
        var rebuilt = lines.join("\r\n")
        # tentar localizar separador de headers original para anexar body (se existia)
        let hdrSep = firstChunk.find("\r\n\r\n")
        if hdrSep >= 0:
          let body = firstChunk.substr(hdrSep + 4)
          rebuilt = rebuilt & "\r\n\r\n" & body
        else:
          rebuilt = rebuilt & "\r\n\r\n"
        # enviar header/body reescrito ao remoto
        try:
          await remote.send(rebuilt)
        except OSError:
          try: client.close() except: discard
          try: remote.close() except: discard
          return
    else:
      # caso não seja absoluta, envia o bloco original
      if firstChunk.len > 0:
        try: await remote.send(firstChunk) except: discard
  else:
    # não-HTTP ou sem reescrita: envia o bloco original
    if firstChunk.len > 0:
      try: await remote.send(firstChunk) except: discard

  # iniciar encaminhamento bidireccional
  asyncCheck copyLoop(client, remote)
  await copyLoop(remote, client)

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
  let opts = ForwardOptions(listenAddr:"127.0.0.1", listenPort:11000.Port, toAddr:"", toPort:0.Port, logFile: "proxyV2.log")
  var f = newForwarder(opts)
  asyncCheck f.serve()
  runForever()










