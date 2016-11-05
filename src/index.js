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
    require('./sniffer')
  })
})
