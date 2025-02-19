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
    public interface IAlipayCommerceLogisticsOrderInstantdeliveryApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 取消即时配送订单
        /// </summary>
        /// <remarks>
        /// 取消即时配送订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCancelModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel</returns>
        AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel Cancel(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel alipayCommerceLogisticsOrderInstantdeliveryCancelModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 取消即时配送订单
        /// </summary>
        /// <remarks>
        /// 取消即时配送订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCancelModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel</returns>
        ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel> CancelWithHttpInfo(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel alipayCommerceLogisticsOrderInstantdeliveryCancelModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 下即时配送订单
        /// </summary>
        /// <remarks>
        /// 下即时配送订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel</returns>
        AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel Create(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel alipayCommerceLogisticsOrderInstantdeliveryCreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 下即时配送订单
        /// </summary>
        /// <remarks>
        /// 下即时配送订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel</returns>
        ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel> CreateWithHttpInfo(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel alipayCommerceLogisticsOrderInstantdeliveryCreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 预下即时配送订单
        /// </summary>
        /// <remarks>
        /// 预下即时配送订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel</returns>
        AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel Precreate(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 预下即时配送订单
        /// </summary>
        /// <remarks>
        /// 预下即时配送订单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel</returns>
        ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel> PrecreateWithHttpInfo(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayCommerceLogisticsOrderInstantdeliveryApi : IAlipayCommerceLogisticsOrderInstantdeliveryApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayCommerceLogisticsOrderInstantdeliveryApi : IAlipayCommerceLogisticsOrderInstantdeliveryApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceLogisticsOrderInstantdeliveryApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayCommerceLogisticsOrderInstantdeliveryApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceLogisticsOrderInstantdeliveryApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayCommerceLogisticsOrderInstantdeliveryApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceLogisticsOrderInstantdeliveryApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayCommerceLogisticsOrderInstantdeliveryApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayCommerceLogisticsOrderInstantdeliveryApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayCommerceLogisticsOrderInstantdeliveryApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 取消即时配送订单 取消即时配送订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCancelModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel</returns>
        public AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel Cancel(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel alipayCommerceLogisticsOrderInstantdeliveryCancelModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel> localVarResponse = CancelWithHttpInfo(alipayCommerceLogisticsOrderInstantdeliveryCancelModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 取消即时配送订单 取消即时配送订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCancelModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel> CancelWithHttpInfo(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel alipayCommerceLogisticsOrderInstantdeliveryCancelModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCancelModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayCommerceLogisticsOrderInstantdeliveryCancelModel;
            }

            localVarRequestOptions.Operation = "AlipayCommerceLogisticsOrderInstantdeliveryApi.Cancel";
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
            var localVarResponse = this.Client.Post<AlipayCommerceLogisticsOrderInstantdeliveryCancelResponseModel>("/v3/alipay/commerce/logistics/order/instantdelivery/cancel", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Cancel", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayCommerceLogisticsOrderInstantdeliveryCancelDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 下即时配送订单 下即时配送订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel</returns>
        public AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel Create(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel alipayCommerceLogisticsOrderInstantdeliveryCreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel> localVarResponse = CreateWithHttpInfo(alipayCommerceLogisticsOrderInstantdeliveryCreateModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 下即时配送订单 下即时配送订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryCreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel> CreateWithHttpInfo(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel alipayCommerceLogisticsOrderInstantdeliveryCreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryCreateModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayCommerceLogisticsOrderInstantdeliveryCreateModel;
            }

            localVarRequestOptions.Operation = "AlipayCommerceLogisticsOrderInstantdeliveryApi.Create";
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
            var localVarResponse = this.Client.Post<AlipayCommerceLogisticsOrderInstantdeliveryCreateResponseModel>("/v3/alipay/commerce/logistics/order/instantdelivery/create", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Create", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayCommerceLogisticsOrderInstantdeliveryCreateDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 预下即时配送订单 预下即时配送订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel</returns>
        public AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel Precreate(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel> localVarResponse = PrecreateWithHttpInfo(alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 预下即时配送订单 预下即时配送订单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel> PrecreateWithHttpInfo(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel = default(AlipayCommerceLogisticsOrderInstantdeliveryPrecreateModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayCommerceLogisticsOrderInstantdeliveryPrecreateModel;
            }

            localVarRequestOptions.Operation = "AlipayCommerceLogisticsOrderInstantdeliveryApi.Precreate";
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
            var localVarResponse = this.Client.Post<AlipayCommerceLogisticsOrderInstantdeliveryPrecreateResponseModel>("/v3/alipay/commerce/logistics/order/instantdelivery/precreate", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Precreate", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayCommerceLogisticsOrderInstantdeliveryPrecreateDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
