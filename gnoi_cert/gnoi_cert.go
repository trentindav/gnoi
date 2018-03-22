/*
Copyright 2018 NoviFlow Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// gNOI client tool to install/list/revoke certificates.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	log "github.com/golang/glog"
	"github.com/google/gnxi/utils"
	"github.com/google/gnxi/utils/credentials"
	pb "github.com/openconfig/gnoi/cert"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	targetAddr   = flag.String("target", "localhost:10161", "Where should I connect to")
	targetName   = flag.String("targetName", "server.com", "Certificate name of the target")
	useTls       = flag.Bool("tls", false, "Use TLS instead of TCP")
	targetCert   = flag.String("targetCert", "", "Path to the Certificate to install in the target")
	targetKey    = flag.String("targetKey", "", "Path to the Private Key to install in the target")
	targetCertId = flag.String("targetCertId", "gnxi", "Certificate Id")
	operation    = flag.String("operation", "get", "Available options: get, install, and revoke")
)

func check(msg string, e error) {
	if e != nil {
		log.Exitf("%v (Error message: %v)", msg, e)
	}
}

func get(ctx context.Context, cli pb.CertificateManagementClient) {
	getCertificatesRequest := &pb.GetCertificatesRequest{}
	response, err := cli.GetCertificates(ctx, getCertificatesRequest)
	check("Get Certificates failed", err)
	log.Info(len(response.CertificateInfo),
		" certificate(s) in GetCertificateResponse")
	utils.PrintProto(response)
}

func install(ctx context.Context, cli pb.CertificateManagementClient) {
	datCert, err := ioutil.ReadFile(*targetCert)
	check(fmt.Sprintf("Problem reading target certificate %v", *targetCert), err)
	cert := &pb.Certificate{
		Type:        pb.CertificateType_CT_X509,
		Certificate: datCert,
	}
	datKey, err := ioutil.ReadFile(*targetKey)
	check(fmt.Sprintf("Problem reading target key %v", *targetKey), err)
	privKey := &pb.KeyPair{
		PrivateKey: datKey,
	}
	loadCertReq := &pb.LoadCertificateRequest{
		Certificate:   cert,
		KeyPair:       privKey,
		CertificateId: *targetCertId,
	}
	installReq := &pb.InstallCertificateRequest_LoadCertificate{
		LoadCertificate: loadCertReq,
	}
	requests := []*pb.InstallCertificateRequest{
		{InstallRequest: installReq},
	}

	stream, err := cli.Install(ctx)
	waitc := make(chan struct{})
	go func() {
		for {
			_, err := stream.Recv()
			if err == io.EOF {
				close(waitc)
				return
			}
			check("Failed to receive a Install certificate response", err)
			log.Info("Install certificate response : success")
		}
	}()
	for _, req := range requests {
		log.Info("Send Install certificate request")
		err := stream.Send(req)
		check("Install stream exception", err)
	}
	stream.CloseSend()
	<-waitc
}

func revoke(ctx context.Context, cli pb.CertificateManagementClient) {
	revokeRequest := &pb.RevokeCertificatesRequest{
		CertificateId: []string{*targetCertId},
	}
	response, err := cli.RevokeCertificates(ctx, revokeRequest)
	check("Problem Revoking certificates", err)
	utils.PrintProto(response)
}

func main() {
	flag.Usage = func() {
		usage := `gNOI Client Example
It can be used to Install and Revoke certificates into the target,
as well as List the currently installed ones.

Usage examples:
# Connect in insecure mode (TCP) and install cert/key pair into the target
$ gnoi_cert -alsologtostderr -target 10.0.0.5:10161 -operation install -targetCert server.crt -targetKey server.key

# Connect with TLS and list all installed certificates
$ gnoi_cert -alsologtostderr -target 10.0.0.5:10161 -operation get -tls -cert client.crt -key client.key -ca ca.crt

# Connect with TLS and revoke the certificate identified by 'certificate_id'
$ gnoi_cert -alsologtostderr -target 10.0.0.5:10161 -operation revoke -tls -cert client.crt -key client.key -ca ca.crt -targetCertId gnxi

`
		fmt.Fprintf(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	var opts []grpc.DialOption
	if *useTls {
		log.Info("Use Secure channel")
		opts = credentials.ClientCredentials(*targetName)
	} else {
		log.Info("Use Insecure channel")
		opts = []grpc.DialOption{}
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.Dial(*targetAddr, opts...)
	check(fmt.Sprintf("Dialing to %v failed", *targetAddr), err)
	defer conn.Close()

	cli := pb.NewCertificateManagementClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	switch *operation {
	case "get":
		get(ctx, cli)
	case "install":
		install(ctx, cli)
	case "revoke":
		revoke(ctx, cli)
	default:
		log.Exitf("Invalid operation: %v", *operation)
	}

}
