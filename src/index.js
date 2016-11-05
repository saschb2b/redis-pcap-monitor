'use strict'

const Hapi = require('hapi')
const Inert = require('inert')
const Vision = require('vision')

const server = new Hapi.Server()
const sessionRoutes = require('./routes/sessions')

server.connection({
  port: 3000
})

server.register([
  Inert,
  Vision,
  {
    'register': require('hapi-swagger'),
    'options': {
      info: {
        'title': 'Test API Documentation'
      }
    }
  },
  {
    'register': require('hapi-redis'),
    'options': {
      host: 'localhost',
      opts: {
        parser: 'javascript'
      }
    }
  },
  sessionRoutes
], (err) => {
  if (err) {
    throw err
  }
  server.start((err) => {
    if (err) {
      throw err
    }
    console.log('Server running at:', server.info.uri)
    
    // start sniffing
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
  })
})
