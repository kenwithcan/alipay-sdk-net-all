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
    public interface IAlipayMarketingActivityDeliverychannelApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 查询可推广渠道
        /// </summary>
        /// <remarks>
        /// 查询可推广渠道。该接口会返回可以投放的所有渠道的详细信息。 其中每个渠道的boothCode含义：boothCode表达的是某个渠道可以投放的展位码。例如：支付结果页PAY_RESULT 其中每个渠道的channel含义：表达的是某个固定的渠道。例如：在boothCode &#x3D; PAY_RESULT 的情况下， channel &#x3D; 商户的pid。 该channel就是一个可以投放的渠道，投放后可以在对应的商户的支付结果页看到优惠券。后续创建投放时根据返回的 channel 选择投放渠道
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMarketingActivityDeliverychannelQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayMarketingActivityDeliverychannelQueryResponseModel</returns>
        AlipayMarketingActivityDeliverychannelQueryResponseModel Query(AlipayMarketingActivityDeliverychannelQueryModel alipayMarketingActivityDeliverychannelQueryModel = default(AlipayMarketingActivityDeliverychannelQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 查询可推广渠道
        /// </summary>
        /// <remarks>
        /// 查询可推广渠道。该接口会返回可以投放的所有渠道的详细信息。 其中每个渠道的boothCode含义：boothCode表达的是某个渠道可以投放的展位码。例如：支付结果页PAY_RESULT 其中每个渠道的channel含义：表达的是某个固定的渠道。例如：在boothCode &#x3D; PAY_RESULT 的情况下， channel &#x3D; 商户的pid。 该channel就是一个可以投放的渠道，投放后可以在对应的商户的支付结果页看到优惠券。后续创建投放时根据返回的 channel 选择投放渠道
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMarketingActivityDeliverychannelQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayMarketingActivityDeliverychannelQueryResponseModel</returns>
        ApiResponse<AlipayMarketingActivityDeliverychannelQueryResponseModel> QueryWithHttpInfo(AlipayMarketingActivityDeliverychannelQueryModel alipayMarketingActivityDeliverychannelQueryModel = default(AlipayMarketingActivityDeliverychannelQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayMarketingActivityDeliverychannelApi : IAlipayMarketingActivityDeliverychannelApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayMarketingActivityDeliverychannelApi : IAlipayMarketingActivityDeliverychannelApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityDeliverychannelApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayMarketingActivityDeliverychannelApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityDeliverychannelApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayMarketingActivityDeliverychannelApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityDeliverychannelApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayMarketingActivityDeliverychannelApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityDeliverychannelApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayMarketingActivityDeliverychannelApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 查询可推广渠道 查询可推广渠道。该接口会返回可以投放的所有渠道的详细信息。 其中每个渠道的boothCode含义：boothCode表达的是某个渠道可以投放的展位码。例如：支付结果页PAY_RESULT 其中每个渠道的channel含义：表达的是某个固定的渠道。例如：在boothCode &#x3D; PAY_RESULT 的情况下， channel &#x3D; 商户的pid。 该channel就是一个可以投放的渠道，投放后可以在对应的商户的支付结果页看到优惠券。后续创建投放时根据返回的 channel 选择投放渠道
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMarketingActivityDeliverychannelQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayMarketingActivityDeliverychannelQueryResponseModel</returns>
        public AlipayMarketingActivityDeliverychannelQueryResponseModel Query(AlipayMarketingActivityDeliverychannelQueryModel alipayMarketingActivityDeliverychannelQueryModel = default(AlipayMarketingActivityDeliverychannelQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayMarketingActivityDeliverychannelQueryResponseModel> localVarResponse = QueryWithHttpInfo(alipayMarketingActivityDeliverychannelQueryModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 查询可推广渠道 查询可推广渠道。该接口会返回可以投放的所有渠道的详细信息。 其中每个渠道的boothCode含义：boothCode表达的是某个渠道可以投放的展位码。例如：支付结果页PAY_RESULT 其中每个渠道的channel含义：表达的是某个固定的渠道。例如：在boothCode &#x3D; PAY_RESULT 的情况下， channel &#x3D; 商户的pid。 该channel就是一个可以投放的渠道，投放后可以在对应的商户的支付结果页看到优惠券。后续创建投放时根据返回的 channel 选择投放渠道
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMarketingActivityDeliverychannelQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayMarketingActivityDeliverychannelQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayMarketingActivityDeliverychannelQueryResponseModel> QueryWithHttpInfo(AlipayMarketingActivityDeliverychannelQueryModel alipayMarketingActivityDeliverychannelQueryModel = default(AlipayMarketingActivityDeliverychannelQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayMarketingActivityDeliverychannelQueryModel;
            }

            localVarRequestOptions.Operation = "AlipayMarketingActivityDeliverychannelApi.Query";
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
            var localVarResponse = this.Client.Post<AlipayMarketingActivityDeliverychannelQueryResponseModel>("/v3/alipay/marketing/activity/deliverychannel/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayMarketingActivityDeliverychannelQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
