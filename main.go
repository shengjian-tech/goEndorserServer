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
	//服务端server.yaml设置 endorserHosts 为本服务地址,设置endorserModule: "proxy"   enableEndorser: true (非必须,主要是 客户端 sdk.yaml 的配置)
	address string = ":8848"
	// 使用 pb.XchainClient 连接xuperchain服务,发起事务处理
	xuperChainHost string = "127.0.0.1:37101"
	// defaultKeyPath 用于签名的证书路径,需要和客户端sdk.yaml中的complianceCheckEndorseServiceAddr保持一致
	// 最好和节点证书隔离,如果使用同一份证书,使用SDK时会出现异常
	defaultKeyPath = "./data/endorser/keys/"

	// 如果使用了监管合约,需要在共识配置xuper.json中配置背书服务收费AK(complianceCheckEndorseServiceFeeAddr)的合约账户,示例如下:
	/*
		, "reserved_contracts": [
		    {
		        "module_name": "native",
		        "contract_name": "identity",
		        "method_name": "verify", //可以设置方法的ACL,背书address才有调用权限,这样就能强制SDK必须开启背书合规性检查了
		        "args":{}
		    }
		]
		,"reserved_whitelist": {
			    "account": "XC9999999999999999@xuper"
		}
	*/
	// 节点AK:负责节点通讯
	// 背书收费AK(complianceCheckEndorseServiceFeeAddr): 需要创建一个合约账号,配置到xuer.json 的 reserved_whitelist,用于白名单收费
	// 背书签名AK(complianceCheckEndorseServiceAddr): 背书签名,最好使用这个账号创建的合约,发布监管合约,方便设置ACL
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
