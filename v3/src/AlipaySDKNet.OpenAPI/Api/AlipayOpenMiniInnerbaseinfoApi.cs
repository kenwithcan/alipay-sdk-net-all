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
    public interface IAlipayOpenMiniInnerbaseinfoApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 内部小程序-应用信息查询
        /// </summary>
        /// <remarks>
        /// 查询小程序应用信息
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="miniAppId">小程序ID，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="instCode">租户code，alipay or taobao (optional)</param>
        /// <param name="miniAppName">小程序name，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="appSubType">小程序类型，TINYAPP_TEMPLATE，TINYAPP_NORMAL，TINYAPP_PLUGIN，使用mini_app_name查询的时候，该字段要求必传。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayOpenMiniInnerbaseinfoQueryResponseModel</returns>
        AlipayOpenMiniInnerbaseinfoQueryResponseModel Query(string miniAppId = default(string), string instCode = default(string), string miniAppName = default(string), string appSubType = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 内部小程序-应用信息查询
        /// </summary>
        /// <remarks>
        /// 查询小程序应用信息
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="miniAppId">小程序ID，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="instCode">租户code，alipay or taobao (optional)</param>
        /// <param name="miniAppName">小程序name，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="appSubType">小程序类型，TINYAPP_TEMPLATE，TINYAPP_NORMAL，TINYAPP_PLUGIN，使用mini_app_name查询的时候，该字段要求必传。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayOpenMiniInnerbaseinfoQueryResponseModel</returns>
        ApiResponse<AlipayOpenMiniInnerbaseinfoQueryResponseModel> QueryWithHttpInfo(string miniAppId = default(string), string instCode = default(string), string miniAppName = default(string), string appSubType = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayOpenMiniInnerbaseinfoApi : IAlipayOpenMiniInnerbaseinfoApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayOpenMiniInnerbaseinfoApi : IAlipayOpenMiniInnerbaseinfoApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerbaseinfoApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayOpenMiniInnerbaseinfoApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerbaseinfoApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayOpenMiniInnerbaseinfoApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerbaseinfoApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayOpenMiniInnerbaseinfoApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayOpenMiniInnerbaseinfoApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayOpenMiniInnerbaseinfoApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 内部小程序-应用信息查询 查询小程序应用信息
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="miniAppId">小程序ID，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="instCode">租户code，alipay or taobao (optional)</param>
        /// <param name="miniAppName">小程序name，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="appSubType">小程序类型，TINYAPP_TEMPLATE，TINYAPP_NORMAL，TINYAPP_PLUGIN，使用mini_app_name查询的时候，该字段要求必传。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayOpenMiniInnerbaseinfoQueryResponseModel</returns>
        public AlipayOpenMiniInnerbaseinfoQueryResponseModel Query(string miniAppId = default(string), string instCode = default(string), string miniAppName = default(string), string appSubType = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayOpenMiniInnerbaseinfoQueryResponseModel> localVarResponse = QueryWithHttpInfo(miniAppId, instCode, miniAppName, appSubType, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 内部小程序-应用信息查询 查询小程序应用信息
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="miniAppId">小程序ID，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="instCode">租户code，alipay or taobao (optional)</param>
        /// <param name="miniAppName">小程序name，mini_app_id 和 mini_app_name 两个需要有其中一个必填，当填了mini_app_id时只使用id去进行查询。 (optional)</param>
        /// <param name="appSubType">小程序类型，TINYAPP_TEMPLATE，TINYAPP_NORMAL，TINYAPP_PLUGIN，使用mini_app_name查询的时候，该字段要求必传。 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayOpenMiniInnerbaseinfoQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayOpenMiniInnerbaseinfoQueryResponseModel> QueryWithHttpInfo(string miniAppId = default(string), string instCode = default(string), string miniAppName = default(string), string appSubType = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (miniAppId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "mini_app_id", miniAppId));
            }
            if (instCode != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "inst_code", instCode));
            }
            if (miniAppName != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "mini_app_name", miniAppName));
            }
            if (appSubType != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "app_sub_type", appSubType));
            }

            localVarRequestOptions.Operation = "AlipayOpenMiniInnerbaseinfoApi.Query";
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
            var localVarResponse = this.Client.Get<AlipayOpenMiniInnerbaseinfoQueryResponseModel>("/v3/alipay/open/mini/innerbaseinfo/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayOpenMiniInnerbaseinfoQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
