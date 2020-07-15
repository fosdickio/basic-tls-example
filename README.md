# Basic TLS Client/Server Example

[![Build Status](https://travis-ci.com/fosdickio/basic-tls-example.svg?branch=master)](https://travis-ci.com/fosdickio/basic-tls-example)

This repository provides a basic application that demonstrates communications between a HTTP client and server using sockets.  These communications are negotiated over TLS and make use of the [Bouncy Castle cryptography APIs](https://bouncycastle.org/).

## Requirements
- Java 11
- Maven

## Instructions
```
mvn clean install
java -jar target/basic-tls-example-1.0.0-SNAPSHOT-uber.jar
```
