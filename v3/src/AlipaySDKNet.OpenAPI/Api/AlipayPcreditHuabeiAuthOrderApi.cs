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
    public interface IAlipayPcreditHuabeiAuthOrderApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 花呗先享订单查询接口
        /// </summary>
        /// <remarks>
        /// 查询花呗先享冻结、解冻订单内容及状态。有3种查询方式。推荐商户优先使用auth_opt_id查询；其次是按照(alipay_user_id,out_request_no)组合方式查询；最后是单独通过out_request_no方式查询。  注意：最后一种方式，仅支持2019年2月15日开始的订单。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authOptId">支付宝侧花呗冻结、解冻操作单据id。在原先的冻结或者解冻接口调用中同步返回给商户，或者通过商户通知返回给商户。按订单号查询时，此字段不可为空。 (optional)</param>
        /// <param name="alipayUserId">买家在支付宝的用户id。通过userid+请求流水号组合查询时，此字段不可为空。 (optional)</param>
        /// <param name="openId">买家在支付宝的用户id (optional)</param>
        /// <param name="outRequestNo">商户原先调用冻结、解冻接口传入的请求流水号。按照流水号查询订单时，此字段不能为空。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayPcreditHuabeiAuthOrderQueryResponseModel</returns>
        AlipayPcreditHuabeiAuthOrderQueryResponseModel Query(string authOptId = default(string), string alipayUserId = default(string), string openId = default(string), string outRequestNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 花呗先享订单查询接口
        /// </summary>
        /// <remarks>
        /// 查询花呗先享冻结、解冻订单内容及状态。有3种查询方式。推荐商户优先使用auth_opt_id查询；其次是按照(alipay_user_id,out_request_no)组合方式查询；最后是单独通过out_request_no方式查询。  注意：最后一种方式，仅支持2019年2月15日开始的订单。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authOptId">支付宝侧花呗冻结、解冻操作单据id。在原先的冻结或者解冻接口调用中同步返回给商户，或者通过商户通知返回给商户。按订单号查询时，此字段不可为空。 (optional)</param>
        /// <param name="alipayUserId">买家在支付宝的用户id。通过userid+请求流水号组合查询时，此字段不可为空。 (optional)</param>
        /// <param name="openId">买家在支付宝的用户id (optional)</param>
        /// <param name="outRequestNo">商户原先调用冻结、解冻接口传入的请求流水号。按照流水号查询订单时，此字段不能为空。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayPcreditHuabeiAuthOrderQueryResponseModel</returns>
        ApiResponse<AlipayPcreditHuabeiAuthOrderQueryResponseModel> QueryWithHttpInfo(string authOptId = default(string), string alipayUserId = default(string), string openId = default(string), string outRequestNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 花呗先享解冻或解约接口
        /// </summary>
        /// <remarks>
        /// 用户已经开通花呗先享协议后，商户通过此接口解冻用户资金池金额，也可以解冻并解约。  如果是解约操作，则要求传入的解冻金额必须等于用户资金池余额。  注意：商户在发起解约前，请务必保证已经结算过用户会员费，一旦解约后，无法发起结算用户会员费操作。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayPcreditHuabeiAuthOrderUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel</returns>
        AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel Unfreeze(AlipayPcreditHuabeiAuthOrderUnfreezeModel alipayPcreditHuabeiAuthOrderUnfreezeModel = default(AlipayPcreditHuabeiAuthOrderUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 花呗先享解冻或解约接口
        /// </summary>
        /// <remarks>
        /// 用户已经开通花呗先享协议后，商户通过此接口解冻用户资金池金额，也可以解冻并解约。  如果是解约操作，则要求传入的解冻金额必须等于用户资金池余额。  注意：商户在发起解约前，请务必保证已经结算过用户会员费，一旦解约后，无法发起结算用户会员费操作。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayPcreditHuabeiAuthOrderUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel</returns>
        ApiResponse<AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel> UnfreezeWithHttpInfo(AlipayPcreditHuabeiAuthOrderUnfreezeModel alipayPcreditHuabeiAuthOrderUnfreezeModel = default(AlipayPcreditHuabeiAuthOrderUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayPcreditHuabeiAuthOrderApi : IAlipayPcreditHuabeiAuthOrderApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayPcreditHuabeiAuthOrderApi : IAlipayPcreditHuabeiAuthOrderApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayPcreditHuabeiAuthOrderApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayPcreditHuabeiAuthOrderApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayPcreditHuabeiAuthOrderApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayPcreditHuabeiAuthOrderApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayPcreditHuabeiAuthOrderApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayPcreditHuabeiAuthOrderApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayPcreditHuabeiAuthOrderApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayPcreditHuabeiAuthOrderApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 花呗先享订单查询接口 查询花呗先享冻结、解冻订单内容及状态。有3种查询方式。推荐商户优先使用auth_opt_id查询；其次是按照(alipay_user_id,out_request_no)组合方式查询；最后是单独通过out_request_no方式查询。  注意：最后一种方式，仅支持2019年2月15日开始的订单。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authOptId">支付宝侧花呗冻结、解冻操作单据id。在原先的冻结或者解冻接口调用中同步返回给商户，或者通过商户通知返回给商户。按订单号查询时，此字段不可为空。 (optional)</param>
        /// <param name="alipayUserId">买家在支付宝的用户id。通过userid+请求流水号组合查询时，此字段不可为空。 (optional)</param>
        /// <param name="openId">买家在支付宝的用户id (optional)</param>
        /// <param name="outRequestNo">商户原先调用冻结、解冻接口传入的请求流水号。按照流水号查询订单时，此字段不能为空。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayPcreditHuabeiAuthOrderQueryResponseModel</returns>
        public AlipayPcreditHuabeiAuthOrderQueryResponseModel Query(string authOptId = default(string), string alipayUserId = default(string), string openId = default(string), string outRequestNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayPcreditHuabeiAuthOrderQueryResponseModel> localVarResponse = QueryWithHttpInfo(authOptId, alipayUserId, openId, outRequestNo, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 花呗先享订单查询接口 查询花呗先享冻结、解冻订单内容及状态。有3种查询方式。推荐商户优先使用auth_opt_id查询；其次是按照(alipay_user_id,out_request_no)组合方式查询；最后是单独通过out_request_no方式查询。  注意：最后一种方式，仅支持2019年2月15日开始的订单。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authOptId">支付宝侧花呗冻结、解冻操作单据id。在原先的冻结或者解冻接口调用中同步返回给商户，或者通过商户通知返回给商户。按订单号查询时，此字段不可为空。 (optional)</param>
        /// <param name="alipayUserId">买家在支付宝的用户id。通过userid+请求流水号组合查询时，此字段不可为空。 (optional)</param>
        /// <param name="openId">买家在支付宝的用户id (optional)</param>
        /// <param name="outRequestNo">商户原先调用冻结、解冻接口传入的请求流水号。按照流水号查询订单时，此字段不能为空。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayPcreditHuabeiAuthOrderQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayPcreditHuabeiAuthOrderQueryResponseModel> QueryWithHttpInfo(string authOptId = default(string), string alipayUserId = default(string), string openId = default(string), string outRequestNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.RequestOptions localVarRequestOptions = new AlipaySDKNet.OpenAPI.Client.RequestOptions();

            string[] _contentTypes = new string[] {
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

            if (authOptId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "auth_opt_id", authOptId));
            }
            if (alipayUserId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "alipay_user_id", alipayUserId));
            }
            if (openId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "open_id", openId));
            }
            if (outRequestNo != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "out_request_no", outRequestNo));
            }

            localVarRequestOptions.Operation = "AlipayPcreditHuabeiAuthOrderApi.Query";
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
            var localVarResponse = this.Client.Get<AlipayPcreditHuabeiAuthOrderQueryResponseModel>("/v3/alipay/pcredit/huabei/auth/order/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayPcreditHuabeiAuthOrderQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 花呗先享解冻或解约接口 用户已经开通花呗先享协议后，商户通过此接口解冻用户资金池金额，也可以解冻并解约。  如果是解约操作，则要求传入的解冻金额必须等于用户资金池余额。  注意：商户在发起解约前，请务必保证已经结算过用户会员费，一旦解约后，无法发起结算用户会员费操作。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayPcreditHuabeiAuthOrderUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel</returns>
        public AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel Unfreeze(AlipayPcreditHuabeiAuthOrderUnfreezeModel alipayPcreditHuabeiAuthOrderUnfreezeModel = default(AlipayPcreditHuabeiAuthOrderUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel> localVarResponse = UnfreezeWithHttpInfo(alipayPcreditHuabeiAuthOrderUnfreezeModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 花呗先享解冻或解约接口 用户已经开通花呗先享协议后，商户通过此接口解冻用户资金池金额，也可以解冻并解约。  如果是解约操作，则要求传入的解冻金额必须等于用户资金池余额。  注意：商户在发起解约前，请务必保证已经结算过用户会员费，一旦解约后，无法发起结算用户会员费操作。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayPcreditHuabeiAuthOrderUnfreezeModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel> UnfreezeWithHttpInfo(AlipayPcreditHuabeiAuthOrderUnfreezeModel alipayPcreditHuabeiAuthOrderUnfreezeModel = default(AlipayPcreditHuabeiAuthOrderUnfreezeModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayPcreditHuabeiAuthOrderUnfreezeModel;
            }

            localVarRequestOptions.Operation = "AlipayPcreditHuabeiAuthOrderApi.Unfreeze";
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
            var localVarResponse = this.Client.Put<AlipayPcreditHuabeiAuthOrderUnfreezeResponseModel>("/v3/alipay/pcredit/huabei/auth/order/unfreeze", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Unfreeze", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayPcreditHuabeiAuthOrderUnfreezeDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
