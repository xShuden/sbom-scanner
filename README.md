# SBOM Scanner

A Go application that generates Software Bill of Materials (SBOM) for your Maven projects and scans for security vulnerabilities.

## Features

- Generate Maven dependency tree
- Create effective POM
- Generate SBOM in CycloneDX format
- Security vulnerability scanning with OSV Scanner
- Detailed reporting with JSON output support

## Requirements

- Go 1.21.3 or higher
- Maven 3.x
- OSV Scanner

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sbom-scanner.git
cd sbom-scanner
```

2. Install dependencies:
```bash
go mod download
```

3. Build the application:
```bash
go build -o sbom-scanner
```

## Usage

```bash
./sbom-scanner -f /path/to/pom.xml -o output/dir --exit-on-vuln=false
```

### Parameters

- `-f, --file`: Path to Maven POM file (required)
- `-o, --output`: Output directory (required)
- `--exit-on-vuln`: Exit program when vulnerability is found (default: false)

### Output Files

The program generates the following files:

- `deps-tree.txt`: Maven dependency tree
- `effective-pom.xml`: Effective POM file
- `sbom.xml`: SBOM in CycloneDX format
- `sbom-vulnerabilities.json`: OSV Scanner security report

## Examples

1. Basic scan:
```bash
./sbom-scanner -f pom.xml -o output
```

2. With vulnerability check:
```bash
./sbom-scanner -f pom.xml -o output --exit-on-vuln=true
```

## Development

### Project Structure

```
.
├── main.go           # Main application code
├── go.mod           # Go module definition
├── go.sum           # Dependency checksums
```

### Code Style

- Follows Go standard code formatting
- Uses custom error types for error handling
- Includes comprehensive logging

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

Please report issues via GitHub Issues.
