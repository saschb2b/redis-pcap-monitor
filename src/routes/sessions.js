'use strict'

const Boom = require('boom')
const uuid = require('node-uuid')
const Joi = require('joi')
const shortid = require('shortid')

exports.register = (server, options, next) => {
  const redisClient = server.plugins['hapi-redis'].client

  server.route({
    method: 'GET',
    path: '/test',
    handler: (request, reply) => {
      reply("Hello world")
    }
  })
  return next()
}

exports.register.attributes = {
  name: 'routes-packages'
}
