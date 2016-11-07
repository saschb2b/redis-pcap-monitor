'use strict'

const Boom = require('boom')
const uuid = require('node-uuid')
const Joi = require('joi')
const shortid = require('shortid')

const pcap = require("pcap")
let pcap_session

let counter = 0

exports.register = (server, options, next) => {
  const redisClient = server.plugins['hapi-redis'].client

  server.route({
    method: 'GET',
    path: '/data',
    handler: (request, reply) => {
      redisClient.hgetall("package:5", function (err, obj) {
        reply(obj)
      })
    }
  })

  server.route({
    method: 'GET',
    path: '/data/start',
    handler: (request, reply) => {
      pcap_session = pcap.createSession("", "tcp")

      pcap_session.on('packet', function (raw_packet) {
        let packet = pcap.decode.packet(raw_packet)
        let ipPackage = packet.payload.payload
        let tcpPackage = ipPackage.payload

        if (ipPackage && ipPackage.version === 4 && tcpPackage) {
          let saddr = ipPackage.saddr.addr[0] * 1000000000 + ipPackage.saddr.addr[1] * 1000000 + ipPackage.saddr.addr[2] * 1000 + ipPackage.saddr.addr[3]
          let daddr = ipPackage.daddr.addr[0] * 1000000000 + ipPackage.daddr.addr[1] * 1000000 + ipPackage.daddr.addr[2] * 1000 + ipPackage.daddr.addr[3]

          let result = {
            saddr,
            daddr,
            sport: tcpPackage.sport,
            dport: tcpPackage.dport,
            timestamp: tcpPackage.options.timestamp,
            length: tcpPackage.dataLength,
            data: tcpPackage.data
          }

          redisClient.hmset(`package:${counter}`,
            "saddr", result.saddr,
            "daddr", result.daddr,
            "sport", result.sport,
            "dport", result.dport,
            "timestamp", result.timestamp,
            "data", result.data,
            "datalength", result.length
            , function (err, res) {})

          counter++

          console.log(result)
        }
      })


      reply(`Listening on ${pcap_session.device_name}`)
    }
  })

  server.route({
    method: 'GET',
    path: '/data/stop',
    handler: (request, reply) => {
      pcap_session.close()

      reply(`Stopped listening on ${pcap_session.device_name}`)
    }
  })
  return next()
}

exports.register.attributes = {
  name: 'routes-packages'
}
