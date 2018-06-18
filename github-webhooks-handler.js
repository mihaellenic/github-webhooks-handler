#!/usr/local/bin/node

var http = require("http"),
  url = require("url"),
  exec = require("child_process").exec,
  crypto = require("crypto");

var config = require("./config.json");
var host = config.server_config.host,
  port = config.server_config.port;

  require('console-stamp')(console, 'yyyy-mm-dd HH:MM:ss.l')

process.on("uncaughtException", function(err) {
  console.error("[exception] " + err);
});

http
  .createServer(function(req, res) {
    var payload = "";

    req.on("data", function(chunk) {
      payload += chunk;
    });

    req.on("end", function() {
      var parsedUrl = url.parse(req.url, true);
      
      console.info(req.method, req.url, 'received from ', req.headers.referer , req.headers['user-agent']);

      // parse request data
      var data = JSON.parse(payload)

      // verify request signature
      var isSignatureCorrect = verifySignature(req.headers['x-hub-signature'], payload)
      if(!isSignatureCorrect) {
        res.writeHead(401, "Not Authorized", { "Content-Type": "text/html" });
        res.end("401 - Not Authorized");
        return;
      }

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

          // execute actions on matching events
          if(matchedEvents.length > 0) {

            matchedEvents.forEach(function(event) {
              console.info('Executing event\'s action:', event.event_name)
              
              exec(event.action, function(error, stdout, stderr) {
                error && console.error('Error while executing ' + event.event_name + ' action:', error )
                stdout && console.info(event.event_name + ' action response:', stdout)
                stderr && console.warn(event.event_name + ' action error', stderr)
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

      // generates a signature (HMAC hex digest of the payload. Generated using the sha1 hash function and the secret as the HMAC key) 
      // and does a time safe compare to the signature receieved in the header
      function verifySignature(xHubSignatureHeader, payload) {
        var secret = require("./config.json").server_config.secret;
        
        if(!xHubSignatureHeader && !secret) {
          return true;
        } else if (!xHubSignatureHeader && secret) {
          console.error('Secret is configured on the local server but the Webhook did not contain signature header.');
          return false;
        } else if (xHubSignatureHeader && !secret) {
          console.error('Webhook contains a signature header but the secret is missing from local server configuration.');
          return false;
        }

        var hmac = crypto.createHmac('sha1', secret);
        hmac.update(payload);

        // perform a timing safe compare
        var requestSignature = xHubSignatureHeader.split('=')[1];
        var generatedSignature = hmac.digest('hex');

        // console.log('Request signature', requestSignature);
        // console.log('Generated signature', generatedSignature);

        var isSignatureValid = crypto.timingSafeEqual(
          Buffer.from(generatedSignature, 'utf8'), 
          Buffer.from(requestSignature, 'utf8'));

        if(!isSignatureValid) {
          console.warn('Request signature is not valid.')
        }

        return isSignatureValid;
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

console.info("Server running at http://" + host + ":" + port);