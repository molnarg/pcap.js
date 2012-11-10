var util = require('util')
  , Stream = require('stream')

function PcapReader() {
  Stream.call(this)

  this.buffers = []
  this.global_header = undefined
  this.state = undefined
  this.remaining = this.process()
}

util.inherits(PcapReader, Stream);

PcapReader.prototype.writable = true
PcapReader.prototype.readable = true

PcapReader.prototype.write = function(buffer) {
  // Collecting the given amount of data, then calling process() with it
  // process() returns the needed data size for the next run

  if (buffer.length === this.remaining) {
    this.remaining = this.process(Buffer.concat(this.buffers.concat(buffer)))
    this.buffers = []

  } else if (buffer.length > this.remaining) {
    var nextBuffer = buffer.slice(this.remaining)
    this.remaining = this.process(Buffer.concat(this.buffers.concat(buffer.slice(0, this.remaining))))
    this.buffers = []
    return this.write(nextBuffer)

  } else {
    this.buffers.push(buffer)
    this.remaining -= buffer.length

  }

  return true
}

PcapReader.prototype.end = function(buffer) {
  if (buffer) this.write(buffer)

  this.emit('end')
}


// States
var GLOBAL_HEADER = 0
  , PACKET_HEADER = 1
  , PACKET        = 2

// Lengths
var GLOBAL_HEADER_LENGTH = 24
  , PACKET_HEADER_LENGTH = 16

PcapReader.prototype.process = function(buffer) {
  if (this.state === undefined) {
    // 1. Waiting for the global header.
    this.state = GLOBAL_HEADER
    return GLOBAL_HEADER_LENGTH

  } else if (this.state === GLOBAL_HEADER) {
    // 2. Processing the received global header and then waiting for packet header.
    this.global_header = this.read_global_header(buffer)
    this.state = PACKET_HEADER
    return PACKET_HEADER_LENGTH

  } else if (this.state === PACKET_HEADER) {
    // 3. Packet header received. Extracting header data and then waiting for the packet data
    this.packet_header = this.read_packet_header(buffer)
    this.state = PACKET
    return this.packet_header.incl_len

  } else if (this.state === PACKET) {
    // 4. Packet data received. Emitting it and then returning to waiting for packet headers.
    this.emit('data', this.read_packet(buffer))
    this.state = PACKET_HEADER
    return PACKET_HEADER_LENGTH

  } else {
    throw new Error('Invalid state.')
  }
}

PcapReader.prototype.read_global_header = function(buffer) {
  var magic_number = buffer.readUInt32LE(0);

  var little_endian
  if (magic_number === 0xa1b2c3d4) {
    little_endian = true

  } else if (magic_number === 0xd4c3b2a1) {
    little_endian = false

  } else {
    throw new Exception('This is not pcap format.')
  }

  var global_header
  if (little_endian) {
    global_header = {
      little_endian: little_endian,
      version_major: buffer.readUInt16LE(4 ),
      version_minor: buffer.readUInt16LE(6 ),
      thiszone:      buffer.readInt32LE (8 ),
      sigfigs:       buffer.readUInt32LE(12),
      snaplen:       buffer.readUInt32LE(16),
      network:       buffer.readUInt32LE(20)
    }

  } else {
    global_header = {
      little_endian: little_endian,
      version_major: buffer.readUInt16BE(4 ),
      version_minor: buffer.readUInt16BE(6 ),
      thiszone:      buffer.readInt32BE (8 ),
      sigfigs:       buffer.readUInt32BE(12),
      snaplen:       buffer.readUInt32BE(16),
      network:       buffer.readUInt32BE(20)
    }

  }

  var version = global_header.version_major + '.' + global_header.version_minor
  if (version !== '2.4') {
    throw new Exception('The pcap file is in an old (' + version + ') format which is not supported.')
  }

  return global_header
}

PcapReader.prototype.read_packet_header = function(buffer) {
  if (this.global_header.little_endian) {
    return {
      ts_sec:   buffer.readUInt32LE(0 ),
      ts_usec:  buffer.readUInt32LE(4 ),
      incl_len: buffer.readUInt32LE(8 ),
      orig_len: buffer.readUInt32LE(12)
    }

  } else {
    return {
      ts_sec:   buffer.readUInt32BE(0 ),
      ts_usec:  buffer.readUInt32BE(4 ),
      incl_len: buffer.readUInt32BE(8 ),
      orig_len: buffer.readUInt32BE(12)
    }

  }
}

PcapReader.prototype.read_packet = function(buffer) {
  buffer.original_length = this.packet_header.orig_len
  buffer.timestamp = (this.packet_header.ts_sec + this.global_header.thiszone)*1000000 + this.packet_header.ts_usec
  buffer.network = this.global_header.network

  return buffer
}

module.exports = PcapReader
