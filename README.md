### 453

A local DNS server that proxies requests to Google Public DNS through their [DNS-over-HTTPS](https://developers.google.com/speed/public-dns/docs/dns-over-https) feature for secure DNS queries.

Thanks to @miekg's [amazing DNS library](https://github.com/miekg/dns), the server is able to support all DNS resource record types.

#### Todo

- [ ] Error handling
- [ ] `edns_client_subnet` support
- [ ] `random_padding` support
