package main

import (
	"log"
	"net"

	"github.com/xuperchain/xuperchain/service/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

const (
	network string = "tcp"
	//客户端sdk.yaml中的 endorseServiceHost 一致,isNeedComplianceCheck也需要设置为true
	//服务端server.yaml设置 endorserHosts 为本服务地址,设置endorserModule: "proxy"   enableEndorser: true
	address string = ":8848"
	// 使用 pb.XchainClient 连接xuperchain服务,发起事务处理
	xuperChainHost string = "192.168.1.121:37108"
	// defaultKeyPath 用于签名的证书路径,需要和客户端sdk.yaml中的complianceCheckEndorseServiceAddr保持一致
	// 最好和节点证书隔离,如果使用同一份证书,使用SDK时会出现异常
	defaultKeyPath = "./data/endorser/keys/"
)

func main() {
	// 监听本地端口
	listener, err := net.Listen(network, address)
	if err != nil {
		log.Fatalf("net.Listen err: %v", err)
	}
	log.Println(address + " net.Listing...")
	maxSize := 200 * 1024 * 1024
	// 新建gRPC的服务端实例
	grpcServer := grpc.NewServer(grpc.MaxRecvMsgSize(maxSize), grpc.MaxSendMsgSize(maxSize))
	diaOpt := grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxSize), grpc.MaxCallSendMsgSize(maxSize))

	grpcOpts := []grpc.DialOption{}
	//grpcOpts = append(grpcOpts, grpc.WithInsecure())
	grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()), diaOpt)
	conn, err := grpc.Dial(xuperChainHost, grpcOpts...)
	if err != nil {
		log.Fatalf("grpc.Dial conn err: %v", err)
	}
	//注册背书服务
	xc := pb.NewXchainClient(conn)
	endorserService := NewDefaultXEndorser(xc)
	pb.RegisterXendorserServer(grpcServer, endorserService)

	reflection.Register(grpcServer)

	// 起服务，阻塞等待
	grpcServer.Serve(listener)

}
