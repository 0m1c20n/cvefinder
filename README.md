### What's cvefinder
**cvefinder** is a tool to obtain vulnerabilities from a URL based on the applications used by the website.

### Requisites
- [Docker](https://www.docker.com/)

### Usage
1. Create docker image
`$ docker build . -t cvefinder:latest`
2. Run container
`$ docker run -it cvefinder python3 cvefinder.py URL`
3. Get results

### Authors
- [0m1c20n](https://github.com/0m1c20n)