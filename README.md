# redis-hapi-university-test
Simple hapi and redis combination for a university project

## Usage
You will need `libpcap` installed. Most OSX machines seem to have it. All major Linux distributions have it available either by default or with a package like `libpcap-dev`.

```
$ docker run --name some-redis -p=6379:6379 -d redis
$ npm i
$ npm start
```

Used docker container: https://hub.docker.com/_/redis/
