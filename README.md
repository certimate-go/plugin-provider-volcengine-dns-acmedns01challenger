# Certimate Volcano Engine DNS plugin

This standalone DNS-01 plugin reuses the built-in `volcengine` access type (`accessKeyId` and `secretAccessKey`). The host supplies the effective TXT record name and value after applying its CNAME and resolver settings. The plugin creates that record and uses the returned record ID for cleanup; it does not delete other TXT values at the same name.

Build the executable with `GOWORK=off go build -o volcengine-dns.exe .`. Run the subprocess integration tests with `GOWORK=off go test ./...`.
