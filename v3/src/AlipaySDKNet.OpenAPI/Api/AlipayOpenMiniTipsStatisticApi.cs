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
    public interface IAlipayOpenMiniTipsStatisticApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 小程序收藏引导汇总数据查询
        /// </summary>
        /// <remarks>
        /// 小程序收藏引导tips文案投放汇总数据查询接口。可查询小程序维度或活动维度的tips曝光uv，收藏uv，以及收藏转化率。请先配置投放活动，否则查询结果返回参数为空。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="deliveryId">收藏引导投放活动ID，供查询收藏引导活动配置接口调用 ，当以小程序维度查询数据（query_type为app）时delivery_id为空 (optional)</param>
        /// <param name="queryType">查询类型，表示以当前维度进行数据聚合。 (optional)</param>
        /// <param name="startDate">查询开始日期，精度为天 (optional)</param>
        /// <param name="endDate">查询截止日期，精度为天 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayOpenMiniTipsStatisticQueryResponseModel</returns>
        AlipayOpenMiniTipsStatisticQueryResponseModel Query(string deliveryId = default(string), string queryType = default(string), string startDate = default(string), string endDate = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 小程序收藏引导汇总数据查询
        /// </summary>
        /// <remarks>
        /// 小程序收藏引导tips文案投放汇总数据查询接口。可查询小程序维度或活动维度的tips曝光uv，收藏uv，以及收藏转化率。请先配置投放活动，否则查询结果返回参数为空。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="deliveryId">收藏引导投放活动ID，供查询收藏引导活动配置接口调用 ，当以小程序维度查询数据（query_type为app）时delivery_id为空 (optional)</param>
        /// <param name="queryType">查询类型，表示以当前维度进行数据聚合。 (optional)</param>
        /// <param name="startDate">查询开始日期，精度为天 (optional)</param>
        /// <param name="endDate">查询截止日期，精度为天 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayOpenMiniTipsStatisticQueryResponseModel</returns>
        ApiResponse<AlipayOpenMiniTipsStatisticQueryResponseModel> QueryWithHttpInfo(string deliveryId = default(string), string queryType = default(string), string startDate = default(string), string endDate = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayOpenMiniTipsStatisticApi : IAlipayOpenMiniTipsStatisticApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayOpenMiniTipsStatisticApi : IAlipayOpenMiniTipsStatisticApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniTipsStatisticApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayOpenMiniTipsStatisticApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniTipsStatisticApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayOpenMiniTipsStatisticApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniTipsStatisticApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayOpenMiniTipsStatisticApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayOpenMiniTipsStatisticApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayOpenMiniTipsStatisticApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 小程序收藏引导汇总数据查询 小程序收藏引导tips文案投放汇总数据查询接口。可查询小程序维度或活动维度的tips曝光uv，收藏uv，以及收藏转化率。请先配置投放活动，否则查询结果返回参数为空。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="deliveryId">收藏引导投放活动ID，供查询收藏引导活动配置接口调用 ，当以小程序维度查询数据（query_type为app）时delivery_id为空 (optional)</param>
        /// <param name="queryType">查询类型，表示以当前维度进行数据聚合。 (optional)</param>
        /// <param name="startDate">查询开始日期，精度为天 (optional)</param>
        /// <param name="endDate">查询截止日期，精度为天 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayOpenMiniTipsStatisticQueryResponseModel</returns>
        public AlipayOpenMiniTipsStatisticQueryResponseModel Query(string deliveryId = default(string), string queryType = default(string), string startDate = default(string), string endDate = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayOpenMiniTipsStatisticQueryResponseModel> localVarResponse = QueryWithHttpInfo(deliveryId, queryType, startDate, endDate, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 小程序收藏引导汇总数据查询 小程序收藏引导tips文案投放汇总数据查询接口。可查询小程序维度或活动维度的tips曝光uv，收藏uv，以及收藏转化率。请先配置投放活动，否则查询结果返回参数为空。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="deliveryId">收藏引导投放活动ID，供查询收藏引导活动配置接口调用 ，当以小程序维度查询数据（query_type为app）时delivery_id为空 (optional)</param>
        /// <param name="queryType">查询类型，表示以当前维度进行数据聚合。 (optional)</param>
        /// <param name="startDate">查询开始日期，精度为天 (optional)</param>
        /// <param name="endDate">查询截止日期，精度为天 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayOpenMiniTipsStatisticQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayOpenMiniTipsStatisticQueryResponseModel> QueryWithHttpInfo(string deliveryId = default(string), string queryType = default(string), string startDate = default(string), string endDate = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (deliveryId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "delivery_id", deliveryId));
            }
            if (queryType != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "query_type", queryType));
            }
            if (startDate != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "start_date", startDate));
            }
            if (endDate != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "end_date", endDate));
            }

            localVarRequestOptions.Operation = "AlipayOpenMiniTipsStatisticApi.Query";
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
            var localVarResponse = this.Client.Get<AlipayOpenMiniTipsStatisticQueryResponseModel>("/v3/alipay/open/mini/tips/statistic/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayOpenMiniTipsStatisticQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
