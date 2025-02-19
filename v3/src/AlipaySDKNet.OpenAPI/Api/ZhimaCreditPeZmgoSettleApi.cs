/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.Mime;
using AlipaySDKNet.OpenAPI.Client;
using AlipaySDKNet.OpenAPI.Model;
using AlipaySDKNet.OpenAPI.Util;
using AlipaySDKNet.OpenAPI.Util.Model;

namespace AlipaySDKNet.OpenAPI.Api
{

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IZhimaCreditPeZmgoSettleApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 芝麻GO结算申请
        /// </summary>
        /// <remarks>
        /// 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleApplyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPeZmgoSettleApplyResponseModel</returns>
        ZhimaCreditPeZmgoSettleApplyResponseModel Apply(ZhimaCreditPeZmgoSettleApplyModel zhimaCreditPeZmgoSettleApplyModel = default(ZhimaCreditPeZmgoSettleApplyModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 芝麻GO结算申请
        /// </summary>
        /// <remarks>
        /// 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleApplyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPeZmgoSettleApplyResponseModel</returns>
        ApiResponse<ZhimaCreditPeZmgoSettleApplyResponseModel> ApplyWithHttpInfo(ZhimaCreditPeZmgoSettleApplyModel zhimaCreditPeZmgoSettleApplyModel = default(ZhimaCreditPeZmgoSettleApplyModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 芝麻GO结算退款接口
        /// </summary>
        /// <remarks>
        /// 芝麻GO结算金额逆向退款接口: 对zhima.credit.pe.zmgo.settle.apply(芝麻GO结算申请接口) 产生的结算交易发起退款操作
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleRefundModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPeZmgoSettleRefundResponseModel</returns>
        ZhimaCreditPeZmgoSettleRefundResponseModel Refund(ZhimaCreditPeZmgoSettleRefundModel zhimaCreditPeZmgoSettleRefundModel = default(ZhimaCreditPeZmgoSettleRefundModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 芝麻GO结算退款接口
        /// </summary>
        /// <remarks>
        /// 芝麻GO结算金额逆向退款接口: 对zhima.credit.pe.zmgo.settle.apply(芝麻GO结算申请接口) 产生的结算交易发起退款操作
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleRefundModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPeZmgoSettleRefundResponseModel</returns>
        ApiResponse<ZhimaCreditPeZmgoSettleRefundResponseModel> RefundWithHttpInfo(ZhimaCreditPeZmgoSettleRefundModel zhimaCreditPeZmgoSettleRefundModel = default(ZhimaCreditPeZmgoSettleRefundModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 芝麻GO解冻接口
        /// </summary>
        /// <remarks>
        /// 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPeZmgoSettleUnfreezeResponseModel</returns>
        ZhimaCreditPeZmgoSettleUnfreezeResponseModel Unfreeze(ZhimaCreditPeZmgoSettleUnfreezeModel zhimaCreditPeZmgoSettleUnfreezeModel = default(ZhimaCreditPeZmgoSettleUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 芝麻GO解冻接口
        /// </summary>
        /// <remarks>
        /// 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPeZmgoSettleUnfreezeResponseModel</returns>
        ApiResponse<ZhimaCreditPeZmgoSettleUnfreezeResponseModel> UnfreezeWithHttpInfo(ZhimaCreditPeZmgoSettleUnfreezeModel zhimaCreditPeZmgoSettleUnfreezeModel = default(ZhimaCreditPeZmgoSettleUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IZhimaCreditPeZmgoSettleApi : IZhimaCreditPeZmgoSettleApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class ZhimaCreditPeZmgoSettleApi : IZhimaCreditPeZmgoSettleApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPeZmgoSettleApi"/> class.
        /// </summary>
        /// <returns></returns>
        public ZhimaCreditPeZmgoSettleApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPeZmgoSettleApi"/> class.
        /// </summary>
        /// <returns></returns>
        public ZhimaCreditPeZmgoSettleApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPeZmgoSettleApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public ZhimaCreditPeZmgoSettleApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
        {
            if (configuration == null) throw new ArgumentNullException("configuration");

            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                configuration
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPeZmgoSettleApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public ZhimaCreditPeZmgoSettleApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
        {
            if (client == null) throw new ArgumentNullException("client");
            if (configuration == null) throw new ArgumentNullException("configuration");

            this.Client = client;
            this.Configuration = configuration;
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }


        /// <summary>
        /// The client for accessing this underlying API synchronously.
        /// </summary>
        public AlipaySDKNet.OpenAPI.Client.ISynchronousClient Client { get; set; }

        /// <summary>
        /// Gets the base path of the API client.
        /// </summary>
        /// <value>The base path</value>
        public string GetBasePath()
        {
            return this.Configuration.BasePath;
        }

        /// <summary>
        /// Gets or sets the configuration object
        /// </summary>
        /// <value>An instance of the Configuration</value>
        public AlipaySDKNet.OpenAPI.Client.IReadableConfiguration Configuration { get; set; }

        /// <summary>
        /// Provides a factory method hook for the creation of exceptions.
        /// </summary>
        public AlipaySDKNet.OpenAPI.Client.ExceptionFactory ExceptionFactory
        {
            get
            {
                if (_exceptionFactory != null && _exceptionFactory.GetInvocationList().Length > 1)
                {
                    throw new InvalidOperationException("Multicast delegate for ExceptionFactory is unsupported.");
                }
                return _exceptionFactory;
            }
            set { _exceptionFactory = value; }
        }

        /// <summary>
        /// 芝麻GO结算申请 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleApplyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPeZmgoSettleApplyResponseModel</returns>
        public ZhimaCreditPeZmgoSettleApplyResponseModel Apply(ZhimaCreditPeZmgoSettleApplyModel zhimaCreditPeZmgoSettleApplyModel = default(ZhimaCreditPeZmgoSettleApplyModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPeZmgoSettleApplyResponseModel> localVarResponse = ApplyWithHttpInfo(zhimaCreditPeZmgoSettleApplyModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 芝麻GO结算申请 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleApplyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPeZmgoSettleApplyResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPeZmgoSettleApplyResponseModel> ApplyWithHttpInfo(ZhimaCreditPeZmgoSettleApplyModel zhimaCreditPeZmgoSettleApplyModel = default(ZhimaCreditPeZmgoSettleApplyModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.RequestOptions localVarRequestOptions = new AlipaySDKNet.OpenAPI.Client.RequestOptions();

            string[] _contentTypes = new string[] {
                "application/json"
            };

            // to determine the Accept header
            string[] _accepts = new string[] {
                "application/json"
            };

            var localVarContentType = AlipaySDKNet.OpenAPI.Client.ClientUtils.SelectHeaderContentType(_contentTypes);
            if (localVarContentType != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Content-Type", localVarContentType);
            }

            var localVarAccept = AlipaySDKNet.OpenAPI.Client.ClientUtils.SelectHeaderAccept(_accepts);
            if (localVarAccept != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Accept", localVarAccept);
            }

            //自定义body内容
            if (customizedParams != null && !string.IsNullOrEmpty(customizedParams.BodyContent))
            {
                localVarRequestOptions.Data = customizedParams.BodyContent;
            }
            else
            {
                localVarRequestOptions.Data = zhimaCreditPeZmgoSettleApplyModel;
            }

            localVarRequestOptions.Operation = "ZhimaCreditPeZmgoSettleApi.Apply";
            localVarRequestOptions.OperationIndex = operationIndex;

            
            if (customizedParams != null)
            {
                //额外query参数
                if (customizedParams.QueryParams != null && customizedParams.QueryParams.Count > 0)
                {
                    foreach (var param in customizedParams.QueryParams)
                    {
                        localVarRequestOptions.QueryParameters.Add(param.Key, param.Value);
                    }
                }

                if (!string.IsNullOrEmpty(customizedParams.AppAuthToken))
                {
                    localVarRequestOptions.HeaderParameters.Add("alipay-app-auth-token", customizedParams.AppAuthToken);
                }
                
                //额外非全局header参数
                if (customizedParams.HeaderParams != null && customizedParams.HeaderParams.Count > 0)
                {
                    foreach (var param in customizedParams.HeaderParams)
                    {
                        localVarRequestOptions.HeaderParameters.Add(param.Key, param.Value);
                    }
                }
            }

            // make the HTTP request
            var localVarResponse = this.Client.Post<ZhimaCreditPeZmgoSettleApplyResponseModel>("/v3/zhima/credit/pe/zmgo/settle/apply", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Apply", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = ZhimaCreditPeZmgoSettleApplyDefaultResponse.FromJson(exception.ErrorContent.ToString());
                        }
                        catch (Exception e)
                        {
                            AlipayLogger.logBizWarn("解析default body内容失败", e);
                        }
                    }
                    throw _exception;
                }
            }

            return localVarResponse;
        }

        /// <summary>
        /// 芝麻GO结算退款接口 芝麻GO结算金额逆向退款接口: 对zhima.credit.pe.zmgo.settle.apply(芝麻GO结算申请接口) 产生的结算交易发起退款操作
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleRefundModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPeZmgoSettleRefundResponseModel</returns>
        public ZhimaCreditPeZmgoSettleRefundResponseModel Refund(ZhimaCreditPeZmgoSettleRefundModel zhimaCreditPeZmgoSettleRefundModel = default(ZhimaCreditPeZmgoSettleRefundModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPeZmgoSettleRefundResponseModel> localVarResponse = RefundWithHttpInfo(zhimaCreditPeZmgoSettleRefundModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 芝麻GO结算退款接口 芝麻GO结算金额逆向退款接口: 对zhima.credit.pe.zmgo.settle.apply(芝麻GO结算申请接口) 产生的结算交易发起退款操作
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleRefundModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPeZmgoSettleRefundResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPeZmgoSettleRefundResponseModel> RefundWithHttpInfo(ZhimaCreditPeZmgoSettleRefundModel zhimaCreditPeZmgoSettleRefundModel = default(ZhimaCreditPeZmgoSettleRefundModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.RequestOptions localVarRequestOptions = new AlipaySDKNet.OpenAPI.Client.RequestOptions();

            string[] _contentTypes = new string[] {
                "application/json"
            };

            // to determine the Accept header
            string[] _accepts = new string[] {
                "application/json"
            };

            var localVarContentType = AlipaySDKNet.OpenAPI.Client.ClientUtils.SelectHeaderContentType(_contentTypes);
            if (localVarContentType != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Content-Type", localVarContentType);
            }

            var localVarAccept = AlipaySDKNet.OpenAPI.Client.ClientUtils.SelectHeaderAccept(_accepts);
            if (localVarAccept != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Accept", localVarAccept);
            }

            //自定义body内容
            if (customizedParams != null && !string.IsNullOrEmpty(customizedParams.BodyContent))
            {
                localVarRequestOptions.Data = customizedParams.BodyContent;
            }
            else
            {
                localVarRequestOptions.Data = zhimaCreditPeZmgoSettleRefundModel;
            }

            localVarRequestOptions.Operation = "ZhimaCreditPeZmgoSettleApi.Refund";
            localVarRequestOptions.OperationIndex = operationIndex;

            
            if (customizedParams != null)
            {
                //额外query参数
                if (customizedParams.QueryParams != null && customizedParams.QueryParams.Count > 0)
                {
                    foreach (var param in customizedParams.QueryParams)
                    {
                        localVarRequestOptions.QueryParameters.Add(param.Key, param.Value);
                    }
                }

                if (!string.IsNullOrEmpty(customizedParams.AppAuthToken))
                {
                    localVarRequestOptions.HeaderParameters.Add("alipay-app-auth-token", customizedParams.AppAuthToken);
                }
                
                //额外非全局header参数
                if (customizedParams.HeaderParams != null && customizedParams.HeaderParams.Count > 0)
                {
                    foreach (var param in customizedParams.HeaderParams)
                    {
                        localVarRequestOptions.HeaderParameters.Add(param.Key, param.Value);
                    }
                }
            }

            // make the HTTP request
            var localVarResponse = this.Client.Post<ZhimaCreditPeZmgoSettleRefundResponseModel>("/v3/zhima/credit/pe/zmgo/settle/refund", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Refund", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = ZhimaCreditPeZmgoSettleRefundDefaultResponse.FromJson(exception.ErrorContent.ToString());
                        }
                        catch (Exception e)
                        {
                            AlipayLogger.logBizWarn("解析default body内容失败", e);
                        }
                    }
                    throw _exception;
                }
            }

            return localVarResponse;
        }

        /// <summary>
        /// 芝麻GO解冻接口 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPeZmgoSettleUnfreezeResponseModel</returns>
        public ZhimaCreditPeZmgoSettleUnfreezeResponseModel Unfreeze(ZhimaCreditPeZmgoSettleUnfreezeModel zhimaCreditPeZmgoSettleUnfreezeModel = default(ZhimaCreditPeZmgoSettleUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPeZmgoSettleUnfreezeResponseModel> localVarResponse = UnfreezeWithHttpInfo(zhimaCreditPeZmgoSettleUnfreezeModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 芝麻GO解冻接口 用户已经开通芝麻GO后，商户通过此接口解冻转支付用户冻结金额。传入金额必须小于等于冻结金额
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPeZmgoSettleUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPeZmgoSettleUnfreezeResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPeZmgoSettleUnfreezeResponseModel> UnfreezeWithHttpInfo(ZhimaCreditPeZmgoSettleUnfreezeModel zhimaCreditPeZmgoSettleUnfreezeModel = default(ZhimaCreditPeZmgoSettleUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.RequestOptions localVarRequestOptions = new AlipaySDKNet.OpenAPI.Client.RequestOptions();

            string[] _contentTypes = new string[] {
                "application/json"
            };

            // to determine the Accept header
            string[] _accepts = new string[] {
                "application/json"
            };

            var localVarContentType = AlipaySDKNet.OpenAPI.Client.ClientUtils.SelectHeaderContentType(_contentTypes);
            if (localVarContentType != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Content-Type", localVarContentType);
            }

            var localVarAccept = AlipaySDKNet.OpenAPI.Client.ClientUtils.SelectHeaderAccept(_accepts);
            if (localVarAccept != null)
            {
                localVarRequestOptions.HeaderParameters.Add("Accept", localVarAccept);
            }

            //自定义body内容
            if (customizedParams != null && !string.IsNullOrEmpty(customizedParams.BodyContent))
            {
                localVarRequestOptions.Data = customizedParams.BodyContent;
            }
            else
            {
                localVarRequestOptions.Data = zhimaCreditPeZmgoSettleUnfreezeModel;
            }

            localVarRequestOptions.Operation = "ZhimaCreditPeZmgoSettleApi.Unfreeze";
            localVarRequestOptions.OperationIndex = operationIndex;

            
            if (customizedParams != null)
            {
                //额外query参数
                if (customizedParams.QueryParams != null && customizedParams.QueryParams.Count > 0)
                {
                    foreach (var param in customizedParams.QueryParams)
                    {
                        localVarRequestOptions.QueryParameters.Add(param.Key, param.Value);
                    }
                }

                if (!string.IsNullOrEmpty(customizedParams.AppAuthToken))
                {
                    localVarRequestOptions.HeaderParameters.Add("alipay-app-auth-token", customizedParams.AppAuthToken);
                }
                
                //额外非全局header参数
                if (customizedParams.HeaderParams != null && customizedParams.HeaderParams.Count > 0)
                {
                    foreach (var param in customizedParams.HeaderParams)
                    {
                        localVarRequestOptions.HeaderParameters.Add(param.Key, param.Value);
                    }
                }
            }

            // make the HTTP request
            var localVarResponse = this.Client.Put<ZhimaCreditPeZmgoSettleUnfreezeResponseModel>("/v3/zhima/credit/pe/zmgo/settle/unfreeze", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Unfreeze", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = ZhimaCreditPeZmgoSettleUnfreezeDefaultResponse.FromJson(exception.ErrorContent.ToString());
                        }
                        catch (Exception e)
                        {
                            AlipayLogger.logBizWarn("解析default body内容失败", e);
                        }
                    }
                    throw _exception;
                }
            }

            return localVarResponse;
        }

    }
}
