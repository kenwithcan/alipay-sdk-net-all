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
    public interface IAlipayEcoEduKtBillingApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 教育缴费账单状态同步接口
        /// </summary>
        /// <remarks>
        /// isv向支付宝－中小学－教育缴费发送教育缴费账单后，家长在支付宝－中小学－教育缴费中对账单完成支付操作且支付成功，ISV在自有系统内容对账，完成后通过此接口同步对账后的账单状态。状态分为：缴费成功、缴费失败。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingModifyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEcoEduKtBillingModifyResponseModel</returns>
        AlipayEcoEduKtBillingModifyResponseModel Modify(AlipayEcoEduKtBillingModifyModel alipayEcoEduKtBillingModifyModel = default(AlipayEcoEduKtBillingModifyModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 教育缴费账单状态同步接口
        /// </summary>
        /// <remarks>
        /// isv向支付宝－中小学－教育缴费发送教育缴费账单后，家长在支付宝－中小学－教育缴费中对账单完成支付操作且支付成功，ISV在自有系统内容对账，完成后通过此接口同步对账后的账单状态。状态分为：缴费成功、缴费失败。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingModifyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEcoEduKtBillingModifyResponseModel</returns>
        ApiResponse<AlipayEcoEduKtBillingModifyResponseModel> ModifyWithHttpInfo(AlipayEcoEduKtBillingModifyModel alipayEcoEduKtBillingModifyModel = default(AlipayEcoEduKtBillingModifyModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 缴费账单查询
        /// </summary>
        /// <remarks>
        /// 缴费账单查询
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="isvPid">Isv pid (optional)</param>
        /// <param name="schoolPid">学校支付宝pid，直付通填写smid (optional)</param>
        /// <param name="outTradeNo">ISV调用发送账单接口，返回给商户的order_no (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEcoEduKtBillingQueryResponseModel</returns>
        AlipayEcoEduKtBillingQueryResponseModel Query(string isvPid = default(string), string schoolPid = default(string), string outTradeNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 缴费账单查询
        /// </summary>
        /// <remarks>
        /// 缴费账单查询
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="isvPid">Isv pid (optional)</param>
        /// <param name="schoolPid">学校支付宝pid，直付通填写smid (optional)</param>
        /// <param name="outTradeNo">ISV调用发送账单接口，返回给商户的order_no (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEcoEduKtBillingQueryResponseModel</returns>
        ApiResponse<AlipayEcoEduKtBillingQueryResponseModel> QueryWithHttpInfo(string isvPid = default(string), string schoolPid = default(string), string outTradeNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 教育缴费账单发送接口
        /// </summary>
        /// <remarks>
        /// 商家发送教育缴费账单给孩子，家长在支付宝可以查看自己绑定的孩子的缴费账单。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingSendModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEcoEduKtBillingSendResponseModel</returns>
        AlipayEcoEduKtBillingSendResponseModel Send(AlipayEcoEduKtBillingSendModel alipayEcoEduKtBillingSendModel = default(AlipayEcoEduKtBillingSendModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 教育缴费账单发送接口
        /// </summary>
        /// <remarks>
        /// 商家发送教育缴费账单给孩子，家长在支付宝可以查看自己绑定的孩子的缴费账单。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingSendModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEcoEduKtBillingSendResponseModel</returns>
        ApiResponse<AlipayEcoEduKtBillingSendResponseModel> SendWithHttpInfo(AlipayEcoEduKtBillingSendModel alipayEcoEduKtBillingSendModel = default(AlipayEcoEduKtBillingSendModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayEcoEduKtBillingApi : IAlipayEcoEduKtBillingApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayEcoEduKtBillingApi : IAlipayEcoEduKtBillingApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEcoEduKtBillingApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayEcoEduKtBillingApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEcoEduKtBillingApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayEcoEduKtBillingApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEcoEduKtBillingApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayEcoEduKtBillingApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayEcoEduKtBillingApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayEcoEduKtBillingApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 教育缴费账单状态同步接口 isv向支付宝－中小学－教育缴费发送教育缴费账单后，家长在支付宝－中小学－教育缴费中对账单完成支付操作且支付成功，ISV在自有系统内容对账，完成后通过此接口同步对账后的账单状态。状态分为：缴费成功、缴费失败。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingModifyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEcoEduKtBillingModifyResponseModel</returns>
        public AlipayEcoEduKtBillingModifyResponseModel Modify(AlipayEcoEduKtBillingModifyModel alipayEcoEduKtBillingModifyModel = default(AlipayEcoEduKtBillingModifyModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEcoEduKtBillingModifyResponseModel> localVarResponse = ModifyWithHttpInfo(alipayEcoEduKtBillingModifyModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 教育缴费账单状态同步接口 isv向支付宝－中小学－教育缴费发送教育缴费账单后，家长在支付宝－中小学－教育缴费中对账单完成支付操作且支付成功，ISV在自有系统内容对账，完成后通过此接口同步对账后的账单状态。状态分为：缴费成功、缴费失败。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingModifyModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEcoEduKtBillingModifyResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEcoEduKtBillingModifyResponseModel> ModifyWithHttpInfo(AlipayEcoEduKtBillingModifyModel alipayEcoEduKtBillingModifyModel = default(AlipayEcoEduKtBillingModifyModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayEcoEduKtBillingModifyModel;
            }

            localVarRequestOptions.Operation = "AlipayEcoEduKtBillingApi.Modify";
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
            var localVarResponse = this.Client.Post<AlipayEcoEduKtBillingModifyResponseModel>("/v3/alipay/eco/edu/kt/billing/modify", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Modify", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayEcoEduKtBillingModifyDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 缴费账单查询 缴费账单查询
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="isvPid">Isv pid (optional)</param>
        /// <param name="schoolPid">学校支付宝pid，直付通填写smid (optional)</param>
        /// <param name="outTradeNo">ISV调用发送账单接口，返回给商户的order_no (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEcoEduKtBillingQueryResponseModel</returns>
        public AlipayEcoEduKtBillingQueryResponseModel Query(string isvPid = default(string), string schoolPid = default(string), string outTradeNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEcoEduKtBillingQueryResponseModel> localVarResponse = QueryWithHttpInfo(isvPid, schoolPid, outTradeNo, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 缴费账单查询 缴费账单查询
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="isvPid">Isv pid (optional)</param>
        /// <param name="schoolPid">学校支付宝pid，直付通填写smid (optional)</param>
        /// <param name="outTradeNo">ISV调用发送账单接口，返回给商户的order_no (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEcoEduKtBillingQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEcoEduKtBillingQueryResponseModel> QueryWithHttpInfo(string isvPid = default(string), string schoolPid = default(string), string outTradeNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (isvPid != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "isv_pid", isvPid));
            }
            if (schoolPid != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "school_pid", schoolPid));
            }
            if (outTradeNo != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "out_trade_no", outTradeNo));
            }

            localVarRequestOptions.Operation = "AlipayEcoEduKtBillingApi.Query";
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
            var localVarResponse = this.Client.Get<AlipayEcoEduKtBillingQueryResponseModel>("/v3/alipay/eco/edu/kt/billing/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayEcoEduKtBillingQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 教育缴费账单发送接口 商家发送教育缴费账单给孩子，家长在支付宝可以查看自己绑定的孩子的缴费账单。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingSendModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEcoEduKtBillingSendResponseModel</returns>
        public AlipayEcoEduKtBillingSendResponseModel Send(AlipayEcoEduKtBillingSendModel alipayEcoEduKtBillingSendModel = default(AlipayEcoEduKtBillingSendModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEcoEduKtBillingSendResponseModel> localVarResponse = SendWithHttpInfo(alipayEcoEduKtBillingSendModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 教育缴费账单发送接口 商家发送教育缴费账单给孩子，家长在支付宝可以查看自己绑定的孩子的缴费账单。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayEcoEduKtBillingSendModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEcoEduKtBillingSendResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEcoEduKtBillingSendResponseModel> SendWithHttpInfo(AlipayEcoEduKtBillingSendModel alipayEcoEduKtBillingSendModel = default(AlipayEcoEduKtBillingSendModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayEcoEduKtBillingSendModel;
            }

            localVarRequestOptions.Operation = "AlipayEcoEduKtBillingApi.Send";
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
            var localVarResponse = this.Client.Post<AlipayEcoEduKtBillingSendResponseModel>("/v3/alipay/eco/edu/kt/billing/send", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Send", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayEcoEduKtBillingSendDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
