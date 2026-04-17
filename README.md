# Remorse API Manager

A flexible, configuration-driven API for executing remote shell commands on multiple servers via SSH. It is designed for reliability with features like command timeouts, concurrency limiting, and detailed logging.

## Features

- **Remote Execution**: Send commands to multiple servers with a single API call.
- **Server Grouping**: Organize servers into logical groups (e.g., "L7", "L4") for targeted commands.
- **Concurrency Limiting**: Set maximum concurrent "attack" slots per group and globally to prevent server overload.
- **Dynamic Commands**: Use placeholders in your commands that are replaced by API parameters at runtime.
- **Configuration Hot-Reload**: Update the server list, methods, and API key without restarting the application.
- **Concurrent Execution**: Commands are dispatched to all target servers simultaneously for high efficiency.
- **Structured JSON Responses**: All API endpoints return clear, machine-readable JSON.
- **Detailed Error Logging**: Failed SSH commands are automatically logged to timestamped files for easy debugging.
- **Command Timeout**: SSH commands automatically time out after 10 seconds to prevent hanging processes.
- **Target Intelligence**: Successful responses include ISP and ASN information for the target.

## Prerequisites

Before you begin, ensure you have the following installed on the machine where you will run this application:

- **Go**: Version 1.22 or newer.
- **sshpass**: A utility for non-interactive SSH password authentication.
  - On Debian/Ubuntu: `sudo apt-get install sshpass`
  - On CentOS/RHEL: `sudo yum install sshpass`
  - On macOS (via Homebrew): `brew install hudochenkov/sshpass/sshpass`

## Setup & Configuration

The entire application is controlled by the `config.json` file.

1.  **Clone/Download**: Place the `main.go`, `go.mod`, and `config.json` files in a directory.
2.  **Edit `config.json`**: Open the `config.json` file and customize it to your needs.

### `config.json` Structure

```json
{
  "apiKey": "your-secret-api-key-change-me",
  "port": "5123",
  "globalMaxConcurrentAttacks": 10,
  "servePublic": false,
  "servers": [
    {
      "name": "server1-l4",
      "host": "192.168.1.100",
      "user": "root",
      "password": "your_server1_password"
    },
    {
      "name": "server2-l4",
      "host": "server2.example.com",
      "user": "admin",
      "password": "your_server2_password"
    }
  ],
  "groups": {
    "L4": {
      "servers": ["server1-l4", "server2-l4"]
    },
    "L7": {
      "servers": ["server2-l4"],
      "maxConcurrentAttacks": 5
    }
  },
  "methods": {
    "NTP_ALL": {
      "command": "/path/to/ntp_script {target} {port} {duration}",
      "group": "Global"
    },
    "TLS_L7": {
      "command": "screen -dmS {screen_name} node tls.js {target} {port} {duration}",
      "group": "L7"
    }
  }
}
```

#### Configuration Fields

- **`apiKey`**: A secret key used to authenticate API requests.
- **`port`**: The port the API server will listen on.
- **`servePublic`**: If `true`, binds to `0.0.0.0` (accessible from other machines). If `false`, binds to `localhost` (accessible only locally).
- **`servers`**: An array of your remote server objects.
  - **`name`**: A unique name to identify the server. This is used in the `groups` section.
  - **`host`**, **`user`**, **`password`**: SSH credentials for the server.
- **`groups`**: An object where you can define collections of servers.
  - The key is the group name (e.g., `"L7"`).
  - The value is an array of server `name`s belonging to that group.
- **`methods`**: An object defining the API methods you can call.
  - The key is the method name (e.g., `"UDP_L7"`).
  - **`command`**: The shell command to execute. It can contain placeholders.
  - **`group`**: The server group to run this command on. Use `"Global"` to target all servers.

#### Command Placeholders

- `{target}`: Replaced by the `target` URL parameter.
- `{port}`: Replaced by the `port` URL parameter.
- `{duration}`: Replaced by the `duration` URL parameter.
- `{screen_name}`: A sanitized name generated if the `{target}` is a URL (e.g., `http://example.com` becomes `examplecom`), perfect for `screen -dmS`.

## Running the Application

Open a terminal in the project directory and run:

```sh
go run .
```

The server will start on the host and port specified in your configuration.

## API Usage

### Execute an Attack

Sends a command to the servers defined by the method's group.

`GET /api/attack`

**Parameters:**
- `auth`: Your `apiKey`.
- `target`: The target IP or URL.
- `port`: The target port.
- `duration`: The duration for the command.
- `method`: The method name defined in `config.json`.

**Example:**
`http://localhost:5123/api/attack?target=1.2.3.4&port=80&duration=120&method=UDP_L7&auth=your-secret-api-key-change-me`

### Reload Configuration

Reloads the `config.json` file without restarting the server.

`GET /api/reload`

**Parameters:**
- `auth`: Your `apiKey`.

**Example:**
`http://localhost:5123/api/reload?auth=your-secret-api-key-change-me`



## Credits

- The whole project was written by @mayshecry on github

- if you want to skid it thats fine but do give credits to me :3
