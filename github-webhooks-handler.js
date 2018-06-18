#!/usr/local/bin/node

var http = require("http"),
  url = require("url"),
  exec = require("child_process").exec,
  crypto = require("crypto");

  require('console-stamp')(console, 'yyyy-mm-dd HH:MM:ss.l')

var config = require("./config.json");

  // hmac.update('secret');


//  console.log("SHA Secret Key", hmac.digest('hex' ))

var host = config.server_config.host,
  port = config.server_config.port,
  serverUrl = "http://" + host + ":" + port,
  secret_key = config.server_config.secret_key;

process.on("uncaughtException", function(err) {
  console.trace("[exception] " + err);
});

http
  .createServer(function(req, res) {
    var req_data = "";

    req.on("data", function(chunk) {
      req_data += chunk;
    });

    req.on("end", function() {
      var parsedUrl = url.parse(req.url, true);
      
      // check authorization
      if (parsedUrl.query["secret_key"] != secret_key) {
        console.info("[warning] Unauthorized request " + req.url);
        res.writeHead(401, "Not Authorized", { "Content-Type": "text/html" });
        res.end("401 - Not Authorized");
        return;
      }

      // parse request data
      var data = JSON.parse(req_data)

      // check security signature
      var hmac = crypto.createHmac('sha1', 'secret');

      hmac.update(req_data);
      var hubSignature = req.headers['x-hub-signature'].split('=')[1];
      var mySignature = hmac.digest('hex')
      console.log("x-github-signature", hubSignature)
      console.log("hmac.digest", mySignature)

      var bufferA = Buffer.from(mySignature, 'utf8')
      var bufferB = Buffer.from(hubSignature, 'utf8')

      var safe = crypto.timingSafeEqual(bufferA, bufferB)

      console.log('are hashes same', safe)

      // get event data from request
      var requestEvent = {
        repository_full_name: data && data.repository && data.repository.full_name,
        ref: data && data.ref,
        event: req.headers["x-github-event"]
      }

      // handle paths
      switch (parsedUrl.pathname) {

        case config.server_config.path:

          var matchedEvents = getMatchingEvents(requestEvent);

          // execute commands if matching events are found
          if(matchedEvents.length > 0) {

            matchedEvents.forEach(function(event) {
              console.info('executing event command:', event)
              
              exec(event.command, function(error, stdout, stderr) {
                error && console.error('Error while executing command:', error )
                stdout && console.info('Command response:', stdout)
                stderr && console.warn("Command error", stderr)
              });

            })

            res.writeHead(200, "OK", { "Content-Type": "text/html" });
            res.end("OK");

          } else {

            res.writeHead(404, "Not found", { "Content-Type": "text/html" });
            res.end("404 - Not found");
            console.log('No matching events found.')

          }
          break;

        default:
          res.writeHead(404, "Not found", { "Content-Type": "text/html" });
          res.end("404 - Not found");
          console.log("[404] " + req.method + " to " + req.url);
      }

      function getMatchingEvents(requestEvent) {
        // fetching events from config here instead of using the config loaded at startup
        // to get the latest changes from the config file
        var events = require("./config.json").events

        // TODO: implement more flexible filtering
        // - dynamic attributes matching
        // - regex values
        var matchedEvents = events.filter(function(event){

          return event.repository_full_name === requestEvent.repository_full_name &&
            event.ref === requestEvent.ref &&
            event.event === requestEvent.event;

        })

        return matchedEvents;
      }
      
    });

  })
  .listen(port, host);

console.info("Server running at " + serverUrl);