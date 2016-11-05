'use strict'

const Boom = require('boom')
const uuid = require('node-uuid')
const Joi = require('joi')
const shortid = require('shortid')

const pcap = require("pcap")
let pcap_session

exports.register = (server, options, next) => {
  const redisClient = server.plugins['hapi-redis'].client

  server.route({
    method: 'GET',
    path: '/data/start',
    handler: (request, reply) => {
      pcap_session = pcap.createSession("", "tcp")

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
