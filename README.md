# What is github-webhooks-handler?
A simple configurable HTTP server written in NodeJS for executing simple actions (shell commands or scripts) on GitHub Webhooks.

# Webhooks Handler server configuration
Configuration is done inside `config.json` file. You can use provided `config.sample.json` file as template for creating you own configuration.

Sample configuration file:
```
{
    "server_config": {
        "host": "0.0.0.0",
        "port": 9005,
        "path": "/update",
        "secret": "sample_secret_key"
    },
    "events": [
        {
            "event_name": "Sample project DEV deploy",
            "repository_full_name": "sample-user/sample-project",
            "ref": "refs/heads/develop",
            "event": "push",
            "action": "echo Hello sample world!"
        }
    ]
}
```

Following is the description of all configuration parameters.

Server configuration:
- `server_config.host` - local interface to expose the server on. Use `localhost` or `127.0.0.1` if you want to expose the server local-only. Use `0.0.0.0` or specific local interface IP address or hostname to expose the server externally.
- `server_config.port` - local port to expose the server on.
- `server_config.path` - Webhooks endpoint path
- `server_config.secret` - Secret key used the webhook signature validation. The same secret key should be entered in the GitHub Webhook configuration.

Events configuration:
- `events` - list of events
- `event.event_name` - User friendly event name
- `event.repository_full_name` - The full name of GitHub repository
- `event.ref` - The name of the fully qualified reference (ie: `ref/heads/develop`)
- `event.event` - Webhook event
- `action` - The bash command to execute when matching Webhook event is recieved

# GitHub Webhook configuration
- `Payload URL` - URL of webhook handler server (i.e. http://my-domain-or-ip:8000)
- `Content Type` - Currently only `application/json` content type is supported
- `Secret` - Secret key used for webhook signature validation. The same secret key should be entered in the webhook server configuration (`server_config.secret`)