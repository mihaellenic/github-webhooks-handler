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
      
      console.info(req.method, req.url, 'received from ', req.headers['user-agent']);

      // verify request signature
      var is_signature_correct = verifySignature(req.headers['x-hub-signature'], payload)
      if(!is_signature_correct) {
        res.writeHead(401, "Not Authorized", { "Content-Type": "text/html" });
        res.end("401 Not Authorized");
        return;
      }

      // parse request data
      var data = JSON.parse(payload);
      var event_type = req.headers["x-github-event"];

      // validate event data
      if (!validateRequestEventData(data)) {
        res.writeHead(400, "Bad request", { "Content-Type": "text/html" });
        res.end("400 Bad Request");
        return;
      }

      // get event data from request
      var request_event = {
        repository_full_name: data.repository.full_name,
        ref: data.ref,
        event: event_type
      }

      // handle paths
      switch (req.url) {

        case config.server_config.path:

          var matched_events = getMatchingEvents(request_event);

          // execute actions on matching events
          if(matched_events.length > 0) {

            matched_events.forEach(function(event) {
              console.info('Executing event\'s action:', event.event_name)
              
              exec(event.action, function(error, stdout, stderr) {
                error && console.error(event.event_name + ' action execution error:', error )
                stdout && console.info(event.event_name + ' action response:', stdout)
                stderr && console.warn(event.event_name + ' action error response', stderr)
              });

            })

            res.writeHead(200, "OK", { "Content-Type": "text/html" });
            res.end("OK");

          } else {

            res.writeHead(404, "Not found", { "Content-Type": "text/html" });
            res.end("404 Not found");
            console.info('No matching events found.')

          }
          break;

        default:
          res.writeHead(404, "Not found", { "Content-Type": "text/html" });
          res.end("404 Not found");
          console.info("[404] " + req.method + " to " + req.url);
      }

      function validateRequestEventData(data) {
        // console.log('validateRequestEventData', data)
        return data && data.repository && data.repository.full_name && data.ref
      }
 
      // generates a signature (HMAC hex digest of the payload. Generated using the sha1 hash function and the secret as the HMAC key) 
      // and does a time safe compare to the signature receieved in the header
      function verifySignature(x_hub_signature_header, payload) {
        var secret = require("./config.json").server_config.secret;
        
        if(!x_hub_signature_header && !secret) {
          console.warn('Secret is not set on this webhook. Consider setting it up to improve security.')
          return true;
        } else if (!x_hub_signature_header && secret) {
          console.error('Secret is configured on the local server but the Webhook did not contain signature header.');
          return false;
        } else if (x_hub_signature_header && !secret) {
          console.error('Webhook contains a signature header but the secret is missing from local server configuration.');
          return false;
        }

        // validate x_hub_signature_header. it should be formatted like: sha1=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        var x_hub_signature = x_hub_signature_header.split('=');
        if(x_hub_signature.length !== 2 || x_hub_signature[0] !== 'sha1' || x_hub_signature[1].length !== 40) {
          console.error('Request signature is not valid (wrong format).');
          return false;
        }
        
        var hmac = crypto.createHmac('sha1', secret);
        hmac.update(payload);

        // perform a timing safe compare
        var request_signature = x_hub_signature[1];
        var generated_signature = hmac.digest('hex');

        // console.log('Request signature', request_signature);
        // console.log('Generated signature', generated_signature);

        var is_signature_valid = crypto.timingSafeEqual(
          Buffer.from(generated_signature, 'utf8'), 
          Buffer.from(request_signature, 'utf8'));

        if(!is_signature_valid) {
          console.error('Request signature is not valid.')
        }

        return is_signature_valid;
      }

      function getMatchingEvents(request_event) {
        // fetching events from config here instead of using the config loaded at startup
        // to get the current content from the config file
        var events = require("./config.json").events

        // TODO: implement more flexible filtering
        // - dynamic attributes matching
        // - regex values
        var matched_events = events.filter(function(event){

          return event.repository_full_name === request_event.repository_full_name &&
            event.ref === request_event.ref &&
            event.event === request_event.event;

        })

        return matched_events;
      }
      
    });

  })
  .listen(port, host);

console.info("Server running at http://" + host + ":" + port);