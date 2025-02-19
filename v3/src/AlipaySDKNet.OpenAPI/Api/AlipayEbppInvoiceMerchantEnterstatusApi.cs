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
    public interface IAlipayEbppInvoiceMerchantEnterstatusApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 商户入驻流程状态查询
        /// </summary>
        /// <remarks>
        /// 提供给替商户批量入驻的服务商，主动查询入驻流程的状态。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="mShortName">商户品牌简称，只能由大写字母、下划线、数字组成，且必须以大写字母开头。 (optional)</param>
        /// <param name="productCode">商户门店入驻的产品码,STANDARD_INVOICE:扫码开票，INVOICE_RETURN:企业自建-发票回传，INVOICE_EXPENSE:发票报销，PAYMENT_OPEN:支付即开票，PAY_FEE_OPEN:缴费后开票。 (optional)</param>
        /// <param name="processId">工单流水号（如果不填则默认查询最近一条工单） (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel</returns>
        AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel Query(string mShortName = default(string), string productCode = default(string), string processId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 商户入驻流程状态查询
        /// </summary>
        /// <remarks>
        /// 提供给替商户批量入驻的服务商，主动查询入驻流程的状态。
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="mShortName">商户品牌简称，只能由大写字母、下划线、数字组成，且必须以大写字母开头。 (optional)</param>
        /// <param name="productCode">商户门店入驻的产品码,STANDARD_INVOICE:扫码开票，INVOICE_RETURN:企业自建-发票回传，INVOICE_EXPENSE:发票报销，PAYMENT_OPEN:支付即开票，PAY_FEE_OPEN:缴费后开票。 (optional)</param>
        /// <param name="processId">工单流水号（如果不填则默认查询最近一条工单） (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel</returns>
        ApiResponse<AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel> QueryWithHttpInfo(string mShortName = default(string), string productCode = default(string), string processId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayEbppInvoiceMerchantEnterstatusApi : IAlipayEbppInvoiceMerchantEnterstatusApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayEbppInvoiceMerchantEnterstatusApi : IAlipayEbppInvoiceMerchantEnterstatusApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceMerchantEnterstatusApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayEbppInvoiceMerchantEnterstatusApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceMerchantEnterstatusApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayEbppInvoiceMerchantEnterstatusApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceMerchantEnterstatusApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayEbppInvoiceMerchantEnterstatusApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceMerchantEnterstatusApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayEbppInvoiceMerchantEnterstatusApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 商户入驻流程状态查询 提供给替商户批量入驻的服务商，主动查询入驻流程的状态。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="mShortName">商户品牌简称，只能由大写字母、下划线、数字组成，且必须以大写字母开头。 (optional)</param>
        /// <param name="productCode">商户门店入驻的产品码,STANDARD_INVOICE:扫码开票，INVOICE_RETURN:企业自建-发票回传，INVOICE_EXPENSE:发票报销，PAYMENT_OPEN:支付即开票，PAY_FEE_OPEN:缴费后开票。 (optional)</param>
        /// <param name="processId">工单流水号（如果不填则默认查询最近一条工单） (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel</returns>
        public AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel Query(string mShortName = default(string), string productCode = default(string), string processId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel> localVarResponse = QueryWithHttpInfo(mShortName, productCode, processId, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 商户入驻流程状态查询 提供给替商户批量入驻的服务商，主动查询入驻流程的状态。
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="mShortName">商户品牌简称，只能由大写字母、下划线、数字组成，且必须以大写字母开头。 (optional)</param>
        /// <param name="productCode">商户门店入驻的产品码,STANDARD_INVOICE:扫码开票，INVOICE_RETURN:企业自建-发票回传，INVOICE_EXPENSE:发票报销，PAYMENT_OPEN:支付即开票，PAY_FEE_OPEN:缴费后开票。 (optional)</param>
        /// <param name="processId">工单流水号（如果不填则默认查询最近一条工单） (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel> QueryWithHttpInfo(string mShortName = default(string), string productCode = default(string), string processId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (mShortName != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "m_short_name", mShortName));
            }
            if (productCode != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "product_code", productCode));
            }
            if (processId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "process_id", processId));
            }

            localVarRequestOptions.Operation = "AlipayEbppInvoiceMerchantEnterstatusApi.Query";
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
            var localVarResponse = this.Client.Get<AlipayEbppInvoiceMerchantEnterstatusQueryResponseModel>("/v3/alipay/ebpp/invoice/merchant/enterstatus/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayEbppInvoiceMerchantEnterstatusQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
