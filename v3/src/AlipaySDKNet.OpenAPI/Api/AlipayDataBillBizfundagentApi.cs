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
    public interface IAlipayDataBillBizfundagentApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// ISV代理商户资金业务账单查询
        /// </summary>
        /// <remarks>
        /// 用于ISV代理商户查询商户的资金业务账单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="startTime">账单查询时间范围 - - 起始时间 (optional)</param>
        /// <param name="endTime">账单查询时间范围 - - 结束范围。时间范围最大不超过31天。 (optional)</param>
        /// <param name="pageNo">页码，从1开始 (optional)</param>
        /// <param name="pageSize">分页大小1000-2000，默认2000 (optional)</param>
        /// <param name="agreementType">根据不同业务协议类型，传入不同参数。传入协议产品码（personal_product_code，通过协议查询接口、协议签约通知响应参数获取），不填的话默认按照示例值传入。 安全发协议：FUND_SAFT_SIGN_WITHHOLDING_P 专用金协议：FLEXIBLE_EMPLOYMENT_SERVICE_P (optional)</param>
        /// <param name="agreementNo">ISV与商户授权协议号 (optional)</param>
        /// <param name="accountBookId">记账本id，服务商在帮助商户开通时候获取的唯一身份号 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayDataBillBizfundagentQueryResponseModel</returns>
        AlipayDataBillBizfundagentQueryResponseModel Query(string startTime = default(string), string endTime = default(string), string pageNo = default(string), string pageSize = default(string), string agreementType = default(string), string agreementNo = default(string), string accountBookId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// ISV代理商户资金业务账单查询
        /// </summary>
        /// <remarks>
        /// 用于ISV代理商户查询商户的资金业务账单
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="startTime">账单查询时间范围 - - 起始时间 (optional)</param>
        /// <param name="endTime">账单查询时间范围 - - 结束范围。时间范围最大不超过31天。 (optional)</param>
        /// <param name="pageNo">页码，从1开始 (optional)</param>
        /// <param name="pageSize">分页大小1000-2000，默认2000 (optional)</param>
        /// <param name="agreementType">根据不同业务协议类型，传入不同参数。传入协议产品码（personal_product_code，通过协议查询接口、协议签约通知响应参数获取），不填的话默认按照示例值传入。 安全发协议：FUND_SAFT_SIGN_WITHHOLDING_P 专用金协议：FLEXIBLE_EMPLOYMENT_SERVICE_P (optional)</param>
        /// <param name="agreementNo">ISV与商户授权协议号 (optional)</param>
        /// <param name="accountBookId">记账本id，服务商在帮助商户开通时候获取的唯一身份号 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayDataBillBizfundagentQueryResponseModel</returns>
        ApiResponse<AlipayDataBillBizfundagentQueryResponseModel> QueryWithHttpInfo(string startTime = default(string), string endTime = default(string), string pageNo = default(string), string pageSize = default(string), string agreementType = default(string), string agreementNo = default(string), string accountBookId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayDataBillBizfundagentApi : IAlipayDataBillBizfundagentApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayDataBillBizfundagentApi : IAlipayDataBillBizfundagentApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayDataBillBizfundagentApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayDataBillBizfundagentApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayDataBillBizfundagentApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayDataBillBizfundagentApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayDataBillBizfundagentApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayDataBillBizfundagentApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayDataBillBizfundagentApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayDataBillBizfundagentApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// ISV代理商户资金业务账单查询 用于ISV代理商户查询商户的资金业务账单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="startTime">账单查询时间范围 - - 起始时间 (optional)</param>
        /// <param name="endTime">账单查询时间范围 - - 结束范围。时间范围最大不超过31天。 (optional)</param>
        /// <param name="pageNo">页码，从1开始 (optional)</param>
        /// <param name="pageSize">分页大小1000-2000，默认2000 (optional)</param>
        /// <param name="agreementType">根据不同业务协议类型，传入不同参数。传入协议产品码（personal_product_code，通过协议查询接口、协议签约通知响应参数获取），不填的话默认按照示例值传入。 安全发协议：FUND_SAFT_SIGN_WITHHOLDING_P 专用金协议：FLEXIBLE_EMPLOYMENT_SERVICE_P (optional)</param>
        /// <param name="agreementNo">ISV与商户授权协议号 (optional)</param>
        /// <param name="accountBookId">记账本id，服务商在帮助商户开通时候获取的唯一身份号 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayDataBillBizfundagentQueryResponseModel</returns>
        public AlipayDataBillBizfundagentQueryResponseModel Query(string startTime = default(string), string endTime = default(string), string pageNo = default(string), string pageSize = default(string), string agreementType = default(string), string agreementNo = default(string), string accountBookId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayDataBillBizfundagentQueryResponseModel> localVarResponse = QueryWithHttpInfo(startTime, endTime, pageNo, pageSize, agreementType, agreementNo, accountBookId, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// ISV代理商户资金业务账单查询 用于ISV代理商户查询商户的资金业务账单
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="startTime">账单查询时间范围 - - 起始时间 (optional)</param>
        /// <param name="endTime">账单查询时间范围 - - 结束范围。时间范围最大不超过31天。 (optional)</param>
        /// <param name="pageNo">页码，从1开始 (optional)</param>
        /// <param name="pageSize">分页大小1000-2000，默认2000 (optional)</param>
        /// <param name="agreementType">根据不同业务协议类型，传入不同参数。传入协议产品码（personal_product_code，通过协议查询接口、协议签约通知响应参数获取），不填的话默认按照示例值传入。 安全发协议：FUND_SAFT_SIGN_WITHHOLDING_P 专用金协议：FLEXIBLE_EMPLOYMENT_SERVICE_P (optional)</param>
        /// <param name="agreementNo">ISV与商户授权协议号 (optional)</param>
        /// <param name="accountBookId">记账本id，服务商在帮助商户开通时候获取的唯一身份号 (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayDataBillBizfundagentQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayDataBillBizfundagentQueryResponseModel> QueryWithHttpInfo(string startTime = default(string), string endTime = default(string), string pageNo = default(string), string pageSize = default(string), string agreementType = default(string), string agreementNo = default(string), string accountBookId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (startTime != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "start_time", startTime));
            }
            if (endTime != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "end_time", endTime));
            }
            if (pageNo != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "page_no", pageNo));
            }
            if (pageSize != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "page_size", pageSize));
            }
            if (agreementType != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "agreement_type", agreementType));
            }
            if (agreementNo != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "agreement_no", agreementNo));
            }
            if (accountBookId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "account_book_id", accountBookId));
            }

            localVarRequestOptions.Operation = "AlipayDataBillBizfundagentApi.Query";
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
            var localVarResponse = this.Client.Get<AlipayDataBillBizfundagentQueryResponseModel>("/v3/alipay/data/bill/bizfundagent/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayDataBillBizfundagentQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
