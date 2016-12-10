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
    path: '/query/connections',
    handler: (request, reply) => {
      redisClient.zrange("timestamp", request.query.start, request.query.end, "WITHSCORES", function (err, obj) {
        reply(obj)
      })
    },
    config: {
      tags: ['api'],
      description: 'Retrieve all connections at a certain point in time',
      validate: {
        query: {
          start: Joi.number().required(),
          end: Joi.number().required()
        }
      }
    }
  })

  server.route({
    method: 'GET',
    path: '/query/datavolume/perminute',
    handler: (request, reply) => {
      redisClient.hmget('datalength', `${request.query.source}:${request.query.destination}`, function (err, obj) {
        reply(obj)
      })
    },
    config: {
      tags: ['api'],
      validate: {
        query: {
          source: Joi.string().required(),
          destination: Joi.string().required()
        }
      }
    }
  })

  server.route({
    method: 'GET',
    path: '/query/hosts/ipport',
    handler: (request, reply) => {
      redisClient.smembers(`hosts:${request.query.destination}:${request.query.port}`, function (err, obj) {
        reply(obj)
      })
    },
    config: {
      tags: ['api'],
      description: 'Retrieve all hosts that had connections to ip a.b.c.d on a specific port',
      validate: {
        query: {
          destination: Joi.number().integer().max(255255255255).required().description('Destination ip'),
          port: Joi.number().integer().min(0).required().description('Destionation port')
        }
      }
    }
  })

  server.route({
    method: 'GET',
    path: '/query/hosts/wellkownports',
    handler: (request, reply) => {
      redisClient.smembers('wellknownports', function (err, obj) {
        reply(obj)
      })
    },
    config: {
      tags: ['api'],
      description: 'Retrieve all hosts that have incoming connections on well-known ports',
    }
  })

  // todo byte sequence

  server.route({
    method: 'GET',
    path: '/query/connections/public',
    handler: (request, reply) => {
      redisClient.zrange("connections", 0, 10000000000, function (err, obj1) {
        redisClient.zrange("connections", 11000000000, 172015255255, function (err, obj2) {
          redisClient.zrange("connections", 172032000000, 192167255255, function (err, obj3) {
            redisClient.zrange("connections", 192169000000, 255255255255, function (err, obj4) {
              reply({
                obj1,
                obj2,
                obj3,
                obj4
              })
            })
          })
        })
      })
    },
    config: {
      tags: ['api'],
      description: 'Retrieve all hosts that have connections to outside hosts'
    }
  })

  server.route({
    method: 'GET',
    path: '/service/pcap/start',
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
            timestamp: tcpPackage.options.timestamp | Date.now(),
            length: tcpPackage.dataLength,
            data: tcpPackage.data
          }
          /*
           redisClient.hmset(`package:${counter}`,
           "saddr", result.saddr,
           "daddr", result.daddr,
           "sport", result.sport,
           "dport", result.dport,
           "timestamp", result.timestamp,
           "data", result.data,
           "datalength", result.length
           , function (err, res) {})
           */
          redisClient.zadd('timestamp',
            result.timestamp, `${result.saddr}:${result.sport}-${result.daddr}:${result.dport}`
          )


          /*
          console.log(typeof result.length)
          if(result.length >= 0 && typeof result.length === 'number') {
            console.log(result.length)
            redisClient.hincrby('datalength', `${result.saddr}:${result.daddr}`, result.length)
          }
*/

          redisClient.sadd(`hosts:${result.daddr}:${result.dport}`, result.saddr)

          if(result.dport <= 1024) {
            redisClient.sadd('wellknownports', `${result.daddr}:${result.dport}`)
          }

          redisClient.zadd('connections',
            result.daddr, result.saddr
          )

          counter++

          console.log(result)
        }
      })


      reply(`Listening on ${pcap_session.device_name}`)
    },
    config: {
      tags: ['api'],
      description: 'Starts pcap'
    }
  })

  server.route({
    method: 'GET',
    path: '/service/pcap/stop',
    handler: (request, reply) => {
      pcap_session.close()

      reply(`Stopped listening on ${pcap_session.device_name}`)
    },
    config: {
      tags: ['api'],
      description: 'Stops pcap'
    }
  })
  return next()
}

exports.register.attributes = {
  name: 'routes-packages'
}
