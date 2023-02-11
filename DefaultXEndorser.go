package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	scom "github.com/xuperchain/xuperchain/service/common"
	"github.com/xuperchain/xuperchain/service/pb"
	"github.com/xuperchain/xupercore/bcs/ledger/xledger/state/utxo/txhash"
	crypto_client "github.com/xuperchain/xupercore/lib/crypto/client"
	"github.com/xuperchain/xupercore/lib/crypto/hash"
)

/*
// 使用 pb.XchainClient,默认实现了这些方法
type XEndorserServer interface {
	// PostTx post Transaction to a node
	PostTx(context.Context, *pb.TxStatus) (*pb.CommonReply, error)
	// QueryTx query Transaction by TxStatus,
	// Bcname and Txid are required for this
	QueryTx(context.Context, *pb.TxStatus) (*pb.TxStatus, error)
	// PreExecWithSelectUTXO preExec & selectUtxo
	PreExecWithSelectUTXO(context.Context, *pb.PreExecWithSelectUTXORequest) (*pb.PreExecWithSelectUTXOResponse, error)
	// 预执行合约
	PreExec(context.Context, *pb.InvokeRPCRequest) (*pb.InvokeRPCResponse, error)
}
type XEndorser interface {
	EndorserCall(gctx context.Context, req *pb.EndorserRequest) (*pb.EndorserResponse, error)
}
*/

// 参照XuperChain的DefaultXEndorser,去掉engine依赖,使用pb.XchainClient处理交易

type DefaultXEndorser struct {
	svr         pb.XchainClient
	requestType map[string]bool
	//engine      ecom.Engine
}

//var _ XEndorser = (*DefaultXEndorser)(nil)

func NewDefaultXEndorser(svr pb.XchainClient) *DefaultXEndorser {
	return &DefaultXEndorser{
		requestType: map[string]bool{
			"PreExecWithFee":    true,
			"ComplianceCheck":   true,
			"CrossQueryPreExec": true,
			"TxQuery":           true,
		},
		svr: svr,
		//engine: engine,
	}
}

// EndorserCall process endorser call
func (dxe *DefaultXEndorser) EndorserCall(ctx context.Context, req *pb.EndorserRequest) (*pb.EndorserResponse, error) {
	// make response header
	resHeader := &pb.Header{
		Error: pb.XChainErrorEnum_SUCCESS,
	}
	if req.GetHeader() == nil {
		resHeader.Logid = req.GetHeader().GetLogid()
	}

	// check param
	if _, ok := dxe.requestType[req.GetRequestName()]; !ok {
		resHeader.Error = pb.XChainErrorEnum_SERVICE_REFUSED_ERROR
		return dxe.generateErrorResponse(req, resHeader, errors.New("request name not supported"))
	}

	// 引用了engine API,暂时去掉了, 在ctx里绑定了 ReqCtxKeyName ,实际并未找到使用的地方,先注释了.
	/*
		reqCtx, err := dxe.createReqCtx(ctx, req.Header)
		if err != nil {
			return nil, err
		}
		ctx = sctx.WithReqCtx(ctx, reqCtx)
	*/

	switch req.GetRequestName() {
	case "ComplianceCheck":
		errCode, err := dxe.processFee(ctx, req)
		if err != nil {
			resHeader.Error = errCode
			return dxe.generateErrorResponse(req, resHeader, err)
		}
		addr, sign, err := dxe.generateTxSign(ctx, req)
		if err != nil {
			resHeader.Error = pb.XChainErrorEnum_SERVICE_REFUSED_ERROR
			return dxe.generateErrorResponse(req, resHeader, err)
		}

		reply := &pb.CommonReply{
			Header: &pb.Header{
				Error: pb.XChainErrorEnum_SUCCESS,
			},
		}
		resData, err := json.Marshal(reply)
		if err != nil {
			resHeader.Error = pb.XChainErrorEnum_SERVICE_REFUSED_ERROR
			return dxe.generateErrorResponse(req, resHeader, err)
		}
		return dxe.generateSuccessResponse(req, resData, addr, sign, resHeader)

	case "PreExecWithFee":
		resData, errCode, err := dxe.getPreExecResult(ctx, req)
		if err != nil {
			resHeader.Error = errCode
			return dxe.generateErrorResponse(req, resHeader, err)
		}
		return dxe.generateSuccessResponse(req, resData, nil, nil, resHeader)

	case "CrossQueryPreExec":
		resData, errCode, err := dxe.getCrossQueryResult(ctx, req)
		resHeader.Error = errCode
		return dxe.genSignedResp(ctx, req, err, resHeader, resData)

	case "TxQuery":
		resData, errCode, err := dxe.getTxResult(ctx, req)
		resHeader.Error = errCode
		return dxe.genSignedResp(ctx, req, err, resHeader, resData)
	}

	return nil, nil
}

// genSignedResp generate response signed by endorser
func (dxe *DefaultXEndorser) genSignedResp(ctx context.Context, req *pb.EndorserRequest, err error,
	resHeader *pb.Header, resData []byte) (*pb.EndorserResponse, error) {

	// failed response for origin request error
	if err != nil {
		return dxe.generateErrorResponse(req, resHeader, err)
	}

	data := append(req.RequestData, resData...)
	digest := hash.UsingSha256(data)
	addr, sign, err := dxe.signData(ctx, digest, defaultKeyPath)
	if err != nil {
		// failed response for sign error
		return dxe.generateErrorResponse(req, resHeader, err)
	}

	// success response
	return dxe.generateSuccessResponse(req, resData, addr, sign, resHeader)
}

func (dxe *DefaultXEndorser) getPreExecResult(ctx context.Context, req *pb.EndorserRequest) ([]byte, pb.XChainErrorEnum, error) {
	request := &pb.PreExecWithSelectUTXORequest{}
	err := json.Unmarshal(req.GetRequestData(), request)
	if err != nil {
		return nil, pb.XChainErrorEnum_SERVICE_REFUSED_ERROR, err
	}

	res, err := dxe.svr.PreExecWithSelectUTXO(ctx, request)
	if err != nil {
		return nil, res.GetHeader().GetError(), err
	}

	sData, err := json.Marshal(res)
	if err != nil {
		return nil, pb.XChainErrorEnum_SERVICE_REFUSED_ERROR, err
	}
	return sData, pb.XChainErrorEnum_SUCCESS, nil
}

func (dxe *DefaultXEndorser) getCrossQueryResult(ctx context.Context, req *pb.EndorserRequest) ([]byte, pb.XChainErrorEnum, error) {
	cqReq := &pb.CrossQueryRequest{}
	err := json.Unmarshal(req.GetRequestData(), cqReq)
	if err != nil {
		return nil, pb.XChainErrorEnum_SERVICE_REFUSED_ERROR, err
	}

	preExecReq := &pb.InvokeRPCRequest{
		Header:      req.GetHeader(),
		Bcname:      cqReq.GetBcname(),
		Initiator:   cqReq.GetInitiator(),
		AuthRequire: cqReq.GetAuthRequire(),
	}
	preExecReq.Requests = append(preExecReq.Requests, cqReq.GetRequest())

	preExecRes, err := dxe.svr.PreExec(ctx, preExecReq)
	if err != nil {
		return nil, preExecRes.GetHeader().GetError(), err
	}

	if preExecRes.GetHeader().GetError() != pb.XChainErrorEnum_SUCCESS {
		return nil, preExecRes.GetHeader().GetError(), errors.New("PreExec not success")
	}

	res := &pb.CrossQueryResponse{}
	contractRes := preExecRes.GetResponse().GetResponses()
	if len(contractRes) > 0 {
		res.Response = contractRes[len(contractRes)-1]
	}

	sData, err := json.Marshal(res)
	if err != nil {
		return nil, pb.XChainErrorEnum_SERVICE_REFUSED_ERROR, err
	}

	return sData, pb.XChainErrorEnum_SUCCESS, nil
}

func (dxe *DefaultXEndorser) getTxResult(ctx context.Context, req *pb.EndorserRequest) ([]byte, pb.XChainErrorEnum, error) {
	request := &pb.TxStatus{}
	err := json.Unmarshal(req.GetRequestData(), request)
	if err != nil {
		return nil, pb.XChainErrorEnum_SERVICE_REFUSED_ERROR, err
	}

	reply, err := dxe.svr.QueryTx(ctx, request)
	if err != nil {
		return nil, reply.GetHeader().GetError(), err
	}

	if reply.GetHeader().GetError() != pb.XChainErrorEnum_SUCCESS {
		return nil, reply.GetHeader().GetError(), errors.New("QueryTx not success")
	}

	if reply.Tx == nil {
		return nil, reply.GetHeader().GetError(), errors.New("tx not found")
	}

	sData, err := json.Marshal(reply.Tx)
	if err != nil {
		return nil, pb.XChainErrorEnum_SERVICE_REFUSED_ERROR, err
	}

	return sData, pb.XChainErrorEnum_SUCCESS, nil
}

func (dxe *DefaultXEndorser) processFee(ctx context.Context, req *pb.EndorserRequest) (pb.XChainErrorEnum, error) {
	if req.GetFee() == nil {
		// no fee provided, default to true
		return pb.XChainErrorEnum_SUCCESS, nil
	}

	txStatus := &pb.TxStatus{
		Txid:   req.GetFee().GetTxid(),
		Bcname: req.GetBcName(),
		Tx:     req.GetFee(),
	}

	res, err := dxe.svr.PostTx(ctx, txStatus)
	errCode := res.GetHeader().GetError()
	if err != nil {
		return errCode, err
	}

	if errCode != pb.XChainErrorEnum_SUCCESS {
		return errCode, errors.New("fee post to chain failed")
	}
	return pb.XChainErrorEnum_SUCCESS, nil
}

func (dxe *DefaultXEndorser) generateTxSign(ctx context.Context, req *pb.EndorserRequest) ([]byte, *pb.SignatureInfo, error) {
	if req.GetRequestData() == nil {
		return nil, nil, errors.New("request data is empty")
	}

	txStatus := &pb.TxStatus{}
	err := json.Unmarshal(req.GetRequestData(), txStatus)
	if err != nil {
		return nil, nil, err
	}

	tx := scom.TxToXledger(txStatus.GetTx())
	digest, err := txhash.MakeTxDigestHash(tx)
	if err != nil {
		return nil, nil, err
	}

	return dxe.signData(ctx, digest, defaultKeyPath)
}

func (dxe *DefaultXEndorser) signData(ctx context.Context, data []byte, keypath string) ([]byte, *pb.SignatureInfo, error) {
	addr, jsonSKey, jsonAKey, err := dxe.getEndorserKey(keypath)
	if err != nil {
		return nil, nil, err
	}

	cryptoClient, err := crypto_client.CreateCryptoClientFromJSONPrivateKey(jsonSKey)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := cryptoClient.GetEcdsaPrivateKeyFromJsonStr(string(jsonSKey))
	if err != nil {
		return nil, nil, err
	}

	sign, err := cryptoClient.SignECDSA(privateKey, data)
	if err != nil {
		return nil, nil, err
	}

	signInfo := &pb.SignatureInfo{
		PublicKey: string(jsonAKey),
		Sign:      sign,
	}
	return addr, signInfo, nil
}

func (dxe *DefaultXEndorser) generateErrorResponse(req *pb.EndorserRequest, header *pb.Header,
	err error) (*pb.EndorserResponse, error) {
	res := &pb.EndorserResponse{
		Header:       header,
		ResponseName: req.GetRequestName(),
	}
	return res, err
}

func (dxe *DefaultXEndorser) generateSuccessResponse(req *pb.EndorserRequest, resData []byte,
	addr []byte, sign *pb.SignatureInfo, header *pb.Header) (*pb.EndorserResponse, error) {
	res := &pb.EndorserResponse{
		Header:          header,
		ResponseName:    req.GetRequestName(),
		ResponseData:    resData,
		EndorserAddress: string(addr),
		EndorserSign:    sign,
	}
	return res, nil
}

func (dxe *DefaultXEndorser) getEndorserKey(keypath string) ([]byte, []byte, []byte, error) {
	sk, err := os.ReadFile(keypath + "private.key")
	if err != nil {
		return nil, nil, nil, err
	}

	ak, err := os.ReadFile(keypath + "public.key")
	if err != nil {
		return nil, nil, nil, err
	}

	addr, err := os.ReadFile(keypath + "address")
	return addr, sk, ak, err
}

/*
func (dxe *DefaultXEndorser) createReqCtx(gctx context.Context, reqHeader *pb.Header) (sctx.ReqCtx, error) {
	// 获取客户端ip
	clientIp, err := dxe.getClietIP(gctx)
	if err != nil {
		return nil, fmt.Errorf("get client ip failed.err:%v", err)
	}

	// 创建请求上下文
	rctx, err := sctx.NewReqCtx(dxe.engine, reqHeader.GetLogid(), clientIp)
	if err != nil {
		return nil, fmt.Errorf("create request context failed.err:%v", err)
	}

	return rctx, nil
}

func (dxe *DefaultXEndorser) getClietIP(gctx context.Context) (string, error) {
	pr, ok := peer.FromContext(gctx)
	if !ok {
		return "", nil
	}

	if pr.Addr == nil || pr.Addr == net.Addr(nil) {
		return "", fmt.Errorf("get client_ip failed because peer.Addr is nil")
	}

	addrSlice := strings.Split(pr.Addr.String(), ":")
	return addrSlice[0], nil
}
*/
