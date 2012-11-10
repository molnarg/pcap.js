var util = require('util')
  , Stream = require('stream')

function PcapWriter() {
  Stream.call(this)
}

util.inherits(PcapWriter, Stream);

PcapWriter.prototype.writable = true
PcapWriter.prototype.readable = true

PcapWriter.prototype.write = function(packet) {
  if (!this.global_header_written) {
    var global_header = new Buffer(24)

    global_header.writeUInt32LE(0xa1b2c3d4    , 0 )
    global_header.writeUInt16LE(2             , 4 )
    global_header.writeUInt16LE(4             , 6 )
    global_header.writeInt32LE (0             , 8 )
    global_header.writeUInt32LE(0             , 12)
    global_header.writeUInt32LE(65535         , 16)
    global_header.writeUInt32LE(packet.network, 20)

    this.emit('data', global_header)

    this.global_header_written = true
  }

  var packet_header = new Buffer(16)

  packet_header.writeUInt32LE(Math.floor(packet.timestamp / 1000000), 0 )
  packet_header.writeUInt32LE(packet.timestamp % 1000000            , 4 )
  packet_header.writeUInt32LE(packet.length                         , 8 )
  packet_header.writeUInt32LE(packet.original_length                , 12)

  this.emit('data', packet_header)
  this.emit('data', packet)
}

PcapWriter.prototype.end = function(buffer) {
  if (buffer) this.write(buffer)

  this.emit('end')
}

module.exports = PcapWriter
