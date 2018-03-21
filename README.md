# gNOI Go Examples

These scripts are just simple example of how gNOI can be used with Go.
For now only some basic Certificate Management RPCs have been implemented

### gNOI Cert
This client can install / revoke / get certificates in the target.

#### Install
Connect in insecure mode (TCP) and install cert/key pair into the target.
Note that only LoadCertificate is supported for now (meaning that the
certificate must be signed before uploading it to the target with
the `-targetCert` option).
```bash
$ gnoi_cert_client -alsologtostderr -target 10.0.0.5:10161 -operation install -targetCert server.crt -targetKey server.key
```

#### Get
Connect with TLS and list all installed certificates
```bash
$ gnoi_cert_client -alsologtostderr -target 10.0.0.5:10161 -operation get -tls -cert client.crt -key client.key -ca ca.crt
```

#### Revoke
Connect with TLS and revoke the certificate identified by 'certificate_id'
```bash
$ gnoi_cert_client -alsologtostderr -target 10.0.0.5:10161 -operation revoke -tls -cert client.crt -key client.key -ca ca.crt -targetCertId gnxi
```
