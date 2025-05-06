# Go2Jail

Go2Jail is a daemon service designed to protect your server by automatically detecting and banning malicious hosts that attempt to attack your server.

## Features

- Real-time server log monitoring
- Automatic malicious behavior detection
- Multiple banning strategies
- Configurable rule system
- IP geolocation lookup
- Email notification system
- HTTP statistics interface

## Installation

### From Source

```bash
git clone https://github.com/yourusername/go2jail.git
cd go2jail
go build
```

### Using Pre-built Binaries

Download the appropriate binary for your system from the [Releases](https://github.com/hanke0/go2jail/releases) page.

## Usage

### Running the Daemon

```bash
go2jail run -c /path/to/config
```

### Testing Configuration

```bash
go2jail test-config -c /path/to/config
```

### Testing Rules

```bash
go2jail test <discipline-id>
```

### Testing Regular Expressions

```bash
go2jail regex -match "pattern" -ignore "pattern" <file>
```

### Testing Email Notifications

```bash
go2jail test-mail <jail-id>
```

### IP Location Lookup

```bash
go2jail ip-location <ip>
```

## Configuration

The configuration file uses YAML format and includes the following sections:

- Logging configuration
- Rule configuration
- Email notification settings
- IP geolocation settings
- HTTP statistics interface settings

For detailed configuration examples, please refer to the `examples` directory.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details. 