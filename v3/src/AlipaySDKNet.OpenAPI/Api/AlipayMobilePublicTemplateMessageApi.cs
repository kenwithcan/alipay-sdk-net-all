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
    public interface IAlipayMobilePublicTemplateMessageApiSync : IApiAccessor
    {
        #region Synchronous Operations
        /// <summary>
        /// 模板消息删除接口
        /// </summary>
        /// <remarks>
        /// 模板消息删除接口
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMobilePublicTemplateMessageDeleteModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>Object</returns>
        Object Delete(AlipayMobilePublicTemplateMessageDeleteModel alipayMobilePublicTemplateMessageDeleteModel = default(AlipayMobilePublicTemplateMessageDeleteModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 模板消息删除接口
        /// </summary>
        /// <remarks>
        /// 模板消息删除接口
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMobilePublicTemplateMessageDeleteModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of Object</returns>
        ApiResponse<Object> DeleteWithHttpInfo(AlipayMobilePublicTemplateMessageDeleteModel alipayMobilePublicTemplateMessageDeleteModel = default(AlipayMobilePublicTemplateMessageDeleteModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 模板消息领取接口
        /// </summary>
        /// <remarks>
        /// 帮助服务窗从服务窗平台（fuwu.alipay.com）公共模板库里领取一个行业的消息模板- -消息模板是一种消息的样式，如消费提醒、账单提醒等
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="templateId">消息母板id (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayMobilePublicTemplateMessageGetResponseModel</returns>
        AlipayMobilePublicTemplateMessageGetResponseModel Get(string templateId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 模板消息领取接口
        /// </summary>
        /// <remarks>
        /// 帮助服务窗从服务窗平台（fuwu.alipay.com）公共模板库里领取一个行业的消息模板- -消息模板是一种消息的样式，如消费提醒、账单提醒等
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="templateId">消息母板id (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayMobilePublicTemplateMessageGetResponseModel</returns>
        ApiResponse<AlipayMobilePublicTemplateMessageGetResponseModel> GetWithHttpInfo(string templateId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null);
        /// <summary>
        /// 模板消息查询接口
        /// </summary>
        /// <remarks>
        /// 模板消息查询接口
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authToken">用户授权令牌 (optional)</param>
        /// <param name="alipayMobilePublicTemplateMessageQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayMobilePublicTemplateMessageQueryResponseModel</returns>
        AlipayMobilePublicTemplateMessageQueryResponseModel Query(string authToken = default(string), AlipayMobilePublicTemplateMessageQueryModel alipayMobilePublicTemplateMessageQueryModel = default(AlipayMobilePublicTemplateMessageQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null);

        /// <summary>
        /// 模板消息查询接口
        /// </summary>
        /// <remarks>
        /// 模板消息查询接口
        /// </remarks>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authToken">用户授权令牌 (optional)</param>
        /// <param name="alipayMobilePublicTemplateMessageQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayMobilePublicTemplateMessageQueryResponseModel</returns>
        ApiResponse<AlipayMobilePublicTemplateMessageQueryResponseModel> QueryWithHttpInfo(string authToken = default(string), AlipayMobilePublicTemplateMessageQueryModel alipayMobilePublicTemplateMessageQueryModel = default(AlipayMobilePublicTemplateMessageQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null);
        #endregion Synchronous Operations
    }


    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public interface IAlipayMobilePublicTemplateMessageApi : IAlipayMobilePublicTemplateMessageApiSync
    {

    }

    /// <summary>
    /// Represents a collection of functions to interact with the API endpoints
    /// </summary>
    public partial class AlipayMobilePublicTemplateMessageApi : IAlipayMobilePublicTemplateMessageApi
    {
        private AlipaySDKNet.OpenAPI.Client.ExceptionFactory _exceptionFactory = (name, response) => null;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMobilePublicTemplateMessageApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayMobilePublicTemplateMessageApi() : this((string)null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMobilePublicTemplateMessageApi"/> class.
        /// </summary>
        /// <returns></returns>
        public AlipayMobilePublicTemplateMessageApi(string basePath)
        {
            this.Configuration = AlipaySDKNet.OpenAPI.Client.Configuration.MergeConfigurations(
                AlipaySDKNet.OpenAPI.Client.GlobalConfiguration.Instance,
                new AlipaySDKNet.OpenAPI.Client.Configuration { BasePath = basePath }
            );
            this.Client = new AlipaySDKNet.OpenAPI.Client.ApiClient(this.Configuration.BasePath);
            this.ExceptionFactory = AlipaySDKNet.OpenAPI.Client.Configuration.DefaultExceptionFactory;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMobilePublicTemplateMessageApi"/> class
        /// using Configuration object
        /// </summary>
        /// <param name="configuration">An instance of Configuration</param>
        /// <returns></returns>
        public AlipayMobilePublicTemplateMessageApi(AlipaySDKNet.OpenAPI.Client.Configuration configuration)
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
        /// Initializes a new instance of the <see cref="AlipayMobilePublicTemplateMessageApi"/> class
        /// using a Configuration object and client instance.
        /// </summary>
        /// <param name="client">The client interface for synchronous API access.</param>
        /// <param name="configuration">The configuration object.</param>
        public AlipayMobilePublicTemplateMessageApi(AlipaySDKNet.OpenAPI.Client.ISynchronousClient client, AlipaySDKNet.OpenAPI.Client.IReadableConfiguration configuration)
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
        /// 模板消息删除接口 模板消息删除接口
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMobilePublicTemplateMessageDeleteModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>Object</returns>
        public Object Delete(AlipayMobilePublicTemplateMessageDeleteModel alipayMobilePublicTemplateMessageDeleteModel = default(AlipayMobilePublicTemplateMessageDeleteModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<Object> localVarResponse = DeleteWithHttpInfo(alipayMobilePublicTemplateMessageDeleteModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 模板消息删除接口 模板消息删除接口
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="alipayMobilePublicTemplateMessageDeleteModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of Object</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<Object> DeleteWithHttpInfo(AlipayMobilePublicTemplateMessageDeleteModel alipayMobilePublicTemplateMessageDeleteModel = default(AlipayMobilePublicTemplateMessageDeleteModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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
                localVarRequestOptions.Data = alipayMobilePublicTemplateMessageDeleteModel;
            }

            localVarRequestOptions.Operation = "AlipayMobilePublicTemplateMessageApi.Delete";
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
            var localVarResponse = this.Client.Post<Object>("/v3/alipay/mobile/public/template/message/delete", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Delete", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayMobilePublicTemplateMessageDeleteDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 模板消息领取接口 帮助服务窗从服务窗平台（fuwu.alipay.com）公共模板库里领取一个行业的消息模板- -消息模板是一种消息的样式，如消费提醒、账单提醒等
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="templateId">消息母板id (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayMobilePublicTemplateMessageGetResponseModel</returns>
        public AlipayMobilePublicTemplateMessageGetResponseModel Get(string templateId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayMobilePublicTemplateMessageGetResponseModel> localVarResponse = GetWithHttpInfo(templateId, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 模板消息领取接口 帮助服务窗从服务窗平台（fuwu.alipay.com）公共模板库里领取一个行业的消息模板- -消息模板是一种消息的样式，如消费提醒、账单提醒等
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="templateId">消息母板id (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayMobilePublicTemplateMessageGetResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayMobilePublicTemplateMessageGetResponseModel> GetWithHttpInfo(string templateId = default(string), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (templateId != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "template_id", templateId));
            }

            localVarRequestOptions.Operation = "AlipayMobilePublicTemplateMessageApi.Get";
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
            var localVarResponse = this.Client.Get<AlipayMobilePublicTemplateMessageGetResponseModel>("/v3/alipay/mobile/public/template/message/get", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Get", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayMobilePublicTemplateMessageGetDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
        /// 模板消息查询接口 模板消息查询接口
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authToken">用户授权令牌 (optional)</param>
        /// <param name="alipayMobilePublicTemplateMessageQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>AlipayMobilePublicTemplateMessageQueryResponseModel</returns>
        public AlipayMobilePublicTemplateMessageQueryResponseModel Query(string authToken = default(string), AlipayMobilePublicTemplateMessageQueryModel alipayMobilePublicTemplateMessageQueryModel = default(AlipayMobilePublicTemplateMessageQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null)
        {
            AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayMobilePublicTemplateMessageQueryResponseModel> localVarResponse = QueryWithHttpInfo(authToken, alipayMobilePublicTemplateMessageQueryModel, operationIndex, customizedParams);
            return localVarResponse.Data;
        }

        /// <summary>
        /// 模板消息查询接口 模板消息查询接口
        /// </summary>
        /// <exception cref="AlipaySDKNet.OpenAPI.Client.ApiException">Thrown when fails to make API call</exception>
        /// <param name="authToken">用户授权令牌 (optional)</param>
        /// <param name="alipayMobilePublicTemplateMessageQueryModel"> (optional)</param>
        /// <param name="operationIndex">Index associated with the operation.</param>
        /// <param name="customizedParams">customizedParams</param>
        /// <returns>ApiResponse of AlipayMobilePublicTemplateMessageQueryResponseModel</returns>
        public AlipaySDKNet.OpenAPI.Client.ApiResponse<AlipayMobilePublicTemplateMessageQueryResponseModel> QueryWithHttpInfo(string authToken = default(string), AlipayMobilePublicTemplateMessageQueryModel alipayMobilePublicTemplateMessageQueryModel = default(AlipayMobilePublicTemplateMessageQueryModel), int operationIndex = 0, CustomizedParams customizedParams = null)
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

            if (authToken != null)
            {
                localVarRequestOptions.QueryParameters.Add(AlipaySDKNet.OpenAPI.Client.ClientUtils.ParameterToMultiMap("", "auth_token", authToken));
            }
            //自定义body内容
            if (customizedParams != null && !string.IsNullOrEmpty(customizedParams.BodyContent))
            {
                localVarRequestOptions.Data = customizedParams.BodyContent;
            }
            else
            {
                localVarRequestOptions.Data = alipayMobilePublicTemplateMessageQueryModel;
            }

            localVarRequestOptions.Operation = "AlipayMobilePublicTemplateMessageApi.Query";
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
            var localVarResponse = this.Client.Post<AlipayMobilePublicTemplateMessageQueryResponseModel>("/v3/alipay/mobile/public/template/message/query", localVarRequestOptions, this.Configuration);
            if (this.ExceptionFactory != null)
            {
                Exception _exception = this.ExceptionFactory("Query", localVarResponse);
                if (_exception != null)
                {
                    if (_exception is ApiException exception && exception.ErrorContent != null)
                    {
                        try
                        {
                            exception.ErrorObject = AlipayMobilePublicTemplateMessageQueryDefaultResponse.FromJson(exception.ErrorContent.ToString());
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
