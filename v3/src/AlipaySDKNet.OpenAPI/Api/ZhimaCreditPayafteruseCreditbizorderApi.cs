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
    public interface IZhimaCreditPayafteruseCreditbizorderApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 结束信用服务订单
        /// </summary>
        /// <remarks>
        /// 结束信用服务订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderFinishModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPayafteruseCreditbizorderFinishResponseModel</returns>
        ZhimaCreditPayafteruseCreditbizorderFinishResponseModel Finish(ZhimaCreditPayafteruseCreditbizorderFinishModel zhimaCreditPayafteruseCreditbizorderFinishModel = default(ZhimaCreditPayafteruseCreditbizorderFinishModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 结束信用服务订单
        /// </summary>
        /// <remarks>
        /// 结束信用服务订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderFinishModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPayafteruseCreditbizorderFinishResponseModel</returns>
        ApiResponse<ZhimaCreditPayafteruseCreditbizorderFinishResponseModel> FinishWithHttpInfo(ZhimaCreditPayafteruseCreditbizorderFinishModel zhimaCreditPayafteruseCreditbizorderFinishModel = default(ZhimaCreditPayafteruseCreditbizorderFinishModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 芝麻信用服务下单（免用户确认场景）
        /// </summary>
        /// <remarks>
        /// 芝麻信用产品免密下单，不需要唤起支付宝APP，通过服务端调用完成下单。 涉及芝麻信用服务产品、芝麻风险评估产品
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderOrderModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPayafteruseCreditbizorderOrderResponseModel</returns>
        ZhimaCreditPayafteruseCreditbizorderOrderResponseModel Order(ZhimaCreditPayafteruseCreditbizorderOrderModel zhimaCreditPayafteruseCreditbizorderOrderModel = default(ZhimaCreditPayafteruseCreditbizorderOrderModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 芝麻信用服务下单（免用户确认场景）
        /// </summary>
        /// <remarks>
        /// 芝麻信用产品免密下单，不需要唤起支付宝APP，通过服务端调用完成下单。 涉及芝麻信用服务产品、芝麻风险评估产品
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderOrderModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPayafteruseCreditbizorderOrderResponseModel</returns>
        ApiResponse<ZhimaCreditPayafteruseCreditbizorderOrderResponseModel> OrderWithHttpInfo(ZhimaCreditPayafteruseCreditbizorderOrderModel zhimaCreditPayafteruseCreditbizorderOrderModel = default(ZhimaCreditPayafteruseCreditbizorderOrderModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 信用服务订单查询
        /// </summary>
        /// <remarks>
        /// 信用服务订单查询
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="creditBizOrderId">信用服务订单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="outOrderNo">商户外部单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPayafteruseCreditbizorderQueryResponseModel</returns>
        ZhimaCreditPayafteruseCreditbizorderQueryResponseModel Query(string creditBizOrderId = default(string), string outOrderNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 信用服务订单查询
        /// </summary>
        /// <remarks>
        /// 信用服务订单查询
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="creditBizOrderId">信用服务订单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="outOrderNo">商户外部单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPayafteruseCreditbizorderQueryResponseModel</returns>
        ApiResponse<ZhimaCreditPayafteruseCreditbizorderQueryResponseModel> QueryWithHttpInfo(string creditBizOrderId = default(string), string outOrderNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IZhimaCreditPayafteruseCreditbizorderApi : IZhimaCreditPayafteruseCreditbizorderApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class ZhimaCreditPayafteruseCreditbizorderApi : IZhimaCreditPayafteruseCreditbizorderApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPayafteruseCreditbizorderApi"/> class.
        /// </summary>
        /// <returns></returns>
        public ZhimaCreditPayafteruseCreditbizorderApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPayafteruseCreditbizorderApi"/> class.
        /// </summary>
        /// <returns></returns>
        public ZhimaCreditPayafteruseCreditbizorderApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPayafteruseCreditbizorderApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public ZhimaCreditPayafteruseCreditbizorderApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="ZhimaCreditPayafteruseCreditbizorderApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public ZhimaCreditPayafteruseCreditbizorderApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 结束信用服务订单 结束信用服务订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderFinishModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPayafteruseCreditbizorderFinishResponseModel</returns>
        public ZhimaCreditPayafteruseCreditbizorderFinishResponseModel Finish(ZhimaCreditPayafteruseCreditbizorderFinishModel zhimaCreditPayafteruseCreditbizorderFinishModel = default(ZhimaCreditPayafteruseCreditbizorderFinishModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPayafteruseCreditbizorderFinishResponseModel> localVarResponse = FinishWithHttpInfo(zhimaCreditPayafteruseCreditbizorderFinishModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 结束信用服务订单 结束信用服务订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderFinishModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPayafteruseCreditbizorderFinishResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPayafteruseCreditbizorderFinishResponseModel> FinishWithHttpInfo(ZhimaCreditPayafteruseCreditbizorderFinishModel zhimaCreditPayafteruseCreditbizorderFinishModel = default(ZhimaCreditPayafteruseCreditbizorderFinishModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = zhimaCreditPayafteruseCreditbizorderFinishModel;
            }

            localVarRequestOptions.Operation = "ZhimaCreditPayafteruseCreditbizorderApi.Finish";
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
            var localVarResponse = this.Client.Post<ZhimaCreditPayafteruseCreditbizorderFinishResponseModel>("/v3/zhima/credit/payafteruse/creditbizorder/finish", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Finish", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = ZhimaCreditPayafteruseCreditbizorderFinishDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 芝麻信用服务下单（免用户确认场景） 芝麻信用产品免密下单，不需要唤起支付宝APP，通过服务端调用完成下单。 涉及芝麻信用服务产品、芝麻风险评估产品
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderOrderModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPayafteruseCreditbizorderOrderResponseModel</returns>
        public ZhimaCreditPayafteruseCreditbizorderOrderResponseModel Order(ZhimaCreditPayafteruseCreditbizorderOrderModel zhimaCreditPayafteruseCreditbizorderOrderModel = default(ZhimaCreditPayafteruseCreditbizorderOrderModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPayafteruseCreditbizorderOrderResponseModel> localVarResponse = OrderWithHttpInfo(zhimaCreditPayafteruseCreditbizorderOrderModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 芝麻信用服务下单（免用户确认场景） 芝麻信用产品免密下单，不需要唤起支付宝APP，通过服务端调用完成下单。 涉及芝麻信用服务产品、芝麻风险评估产品
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="zhimaCreditPayafteruseCreditbizorderOrderModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPayafteruseCreditbizorderOrderResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPayafteruseCreditbizorderOrderResponseModel> OrderWithHttpInfo(ZhimaCreditPayafteruseCreditbizorderOrderModel zhimaCreditPayafteruseCreditbizorderOrderModel = default(ZhimaCreditPayafteruseCreditbizorderOrderModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = zhimaCreditPayafteruseCreditbizorderOrderModel;
            }

            localVarRequestOptions.Operation = "ZhimaCreditPayafteruseCreditbizorderApi.Order";
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
            var localVarResponse = this.Client.Post<ZhimaCreditPayafteruseCreditbizorderOrderResponseModel>("/v3/zhima/credit/payafteruse/creditbizorder/order", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Order", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = ZhimaCreditPayafteruseCreditbizorderOrderDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 信用服务订单查询 信用服务订单查询
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="creditBizOrderId">信用服务订单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="outOrderNo">商户外部单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ZhimaCreditPayafteruseCreditbizorderQueryResponseModel</returns>
        public ZhimaCreditPayafteruseCreditbizorderQueryResponseModel Query(string creditBizOrderId = default(string), string outOrderNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPayafteruseCreditbizorderQueryResponseModel> localVarResponse = QueryWithHttpInfo(creditBizOrderId, outOrderNo, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 信用服务订单查询 信用服务订单查询
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="creditBizOrderId">信用服务订单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="outOrderNo">商户外部单号，out_order_no与credit_biz_order_id至少传一个 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of ZhimaCreditPayafteruseCreditbizorderQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<ZhimaCreditPayafteruseCreditbizorderQueryResponseModel> QueryWithHttpInfo(string creditBizOrderId = default(string), string outOrderNo = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (creditBizOrderId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "credit_biz_order_id", creditBizOrderId));
            }
            if (outOrderNo != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "out_order_no", outOrderNo));
            }

            localVarRequestOptions.Operation = "ZhimaCreditPayafteruseCreditbizorderApi.Query";
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
            var localVarResponse = this.Client.Get<ZhimaCreditPayafteruseCreditbizorderQueryResponseModel>("/v3/zhima/credit/payafteruse/creditbizorder/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = ZhimaCreditPayafteruseCreditbizorderQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
