const pcap = require("pcap")
const pcap_session = pcap.createSession("", "tcp")

console.log('Sniffer started')
console.log("Listening on " + pcap_session.device_name)

pcap_session.on('packet', function (raw_packet) {
  let packet = pcap.decode.packet(raw_packet)
  let ipPackage = packet.payload.payload
  let tcpPackage = ipPackage.payload

  if (ipPackage && tcpPackage) {
    let result = {
      saddr: ipPackage.saddr,
      daddr: ipPackage.daddr,
      sport: tcpPackage.sport,
      dport: tcpPackage.dport,
      timestamp: tcpPackage.options.timestamp,
      length: tcpPackage.dataLength,
      data: tcpPackage.data
    }
    console.log(result)
  }
})
