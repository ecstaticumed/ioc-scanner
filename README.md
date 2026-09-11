# IOC Scanner

A lightweight Python-based Indicators of Compromise (IOC) scanner for identifying and correlating IP addresses, domains, URLs, and file hashes against a local threat-intelligence database.

## Features

- IPv4 and IPv6 identification
- Domain identification
- URL identification
- MD5 detection
- SHA1 detection
- SHA256 detection
- IOC normalization
- Local IOC correlation
- Basic risk classification
- JSON output
- Command-line interface
- Unit tests

## Architecture

```text
                    IOC Scanner
                         |
                         v
                  IOC Classifier
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
         IP           Domain           URL
          |              |              |
          +--------------+--------------+
                         |
                         v
                  Local IOC Database
                         |
                         v
                    Correlation
                         |
                +--------+--------+
                |                 |
                v                 v
             MATCH            NO_MATCH
                |                 |
                v                 v
              HIGH             UNKNOWN
                         |
                         v
                    CLI / JSON
