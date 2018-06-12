#!/usr/local/bin/node

var http = require("http"),
  url = require("url"),
  exec = require("child_process").exec;

var config = require("./config.json");

var host = config.local_server_config.host,
  port = config.local_server_config.port,
  thisServerUrl = "http://" + host + ":" + port,
  secret_key = config.local_server_config.secret_key;

process.on("uncaughtException", function(err) {
  console.error("[exception] " + err);
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
        console.warn("[warning] Unauthorized request " + req.url);
        res.writeHead(401, "Not Authorized", { "Content-Type": "text/html" });
        res.end("401 - Not Authorized");
        return;
      }

      // parse request data
      var data = JSON.parse(req_data)

      // get event data
      var requestEvent = {
        repository_full_name: data && data.repository && data.repository.full_name,
        ref: data && data.ref,
        event: req.headers["x-github-event"]
      }

      // handle paths
      switch (parsedUrl.pathname) {

        case "/update":

          var matchedEvents = getMatchingEvents(requestEvent);

          // execute commands if matching events are found
          if(matchedEvents.length > 0) {

            matchedEvents.map(function(event) {
              console.log('executing event commant', event)
              exec(event.command, function(error, stdout, stderr) {});
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

      // filter and return events from the config
      function getMatchingEvents(requestEvent) {
        // fetching events from config here instead of using the config loaded at startup
        // to get the latest changes from the config file
        var events = require("./config.json").events

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

console.log("Server running at " + thisServerUrl);