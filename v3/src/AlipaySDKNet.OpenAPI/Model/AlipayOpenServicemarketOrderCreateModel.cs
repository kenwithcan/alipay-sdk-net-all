/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// AlipayOpenServicemarketOrderCreateModel
    /// </summary>
    [DataContract(Name = "AlipayOpenServicemarketOrderCreateModel")]
    public partial class AlipayOpenServicemarketOrderCreateModel : IEquatable<AlipayOpenServicemarketOrderCreateModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenServicemarketOrderCreateModel" /> class.
        /// </summary>
        /// <param name="appCategoryIds">11_12;12_13。小程序类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目，详细类目可以参考https://docs.alipay.com/isv/10325.</param>
        /// <param name="appDesc">小程序官方示例Demo，展示已支持的接口能力及组件。.</param>
        /// <param name="appEnglishName">小程序应用英文名称.</param>
        /// <param name="appName">小程序应用名称.</param>
        /// <param name="appOrigin">来源的业务方，需要申请.</param>
        /// <param name="appSlogan">小程序应用简介，一句话描述小程序功能.</param>
        /// <param name="marketCode">订购的服务商品ID所在的市场编码。新接入场景必须传递，具体值请联系产品分配。.</param>
        /// <param name="merchandiseId">订购的服务商品ID.</param>
        /// <param name="merchantPid">商户PID.</param>
        /// <param name="miniAppId">一二方支持传入appId.</param>
        /// <param name="miniCategoryIds">新小程序前台类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目_第二个三级类目，详细类目可以通过 https://docs.open.alipay.com/api_49/alipay.open.mini.category.query接口查询mini_category_list，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。使用后不再读取app_category_ids值，老前台类目将废弃.</param>
        /// <param name="outBizNo">比如某种业务标准外部订单号,比如交易外部订单号，代表商户端自己订单号.</param>
        /// <param name="serviceEmail">小程序客服邮箱.</param>
        /// <param name="servicePhone">小程序客服电话.</param>
        public AlipayOpenServicemarketOrderCreateModel(string appCategoryIds = default(string), string appDesc = default(string), string appEnglishName = default(string), string appName = default(string), string appOrigin = default(string), string appSlogan = default(string), string marketCode = default(string), string merchandiseId = default(string), string merchantPid = default(string), string miniAppId = default(string), string miniCategoryIds = default(string), string outBizNo = default(string), string serviceEmail = default(string), string servicePhone = default(string))
        {
            this.AppCategoryIds = appCategoryIds;
            this.AppDesc = appDesc;
            this.AppEnglishName = appEnglishName;
            this.AppName = appName;
            this.AppOrigin = appOrigin;
            this.AppSlogan = appSlogan;
            this.MarketCode = marketCode;
            this.MerchandiseId = merchandiseId;
            this.MerchantPid = merchantPid;
            this.MiniAppId = miniAppId;
            this.MiniCategoryIds = miniCategoryIds;
            this.OutBizNo = outBizNo;
            this.ServiceEmail = serviceEmail;
            this.ServicePhone = servicePhone;
        }

        /// <summary>
        /// 11_12;12_13。小程序类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目，详细类目可以参考https://docs.alipay.com/isv/10325
        /// </summary>
        /// <value>11_12;12_13。小程序类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目，详细类目可以参考https://docs.alipay.com/isv/10325</value>
        [DataMember(Name = "app_category_ids", EmitDefaultValue = false)]
        public string AppCategoryIds { get; set; }

        /// <summary>
        /// 小程序官方示例Demo，展示已支持的接口能力及组件。
        /// </summary>
        /// <value>小程序官方示例Demo，展示已支持的接口能力及组件。</value>
        [DataMember(Name = "app_desc", EmitDefaultValue = false)]
        public string AppDesc { get; set; }

        /// <summary>
        /// 小程序应用英文名称
        /// </summary>
        /// <value>小程序应用英文名称</value>
        [DataMember(Name = "app_english_name", EmitDefaultValue = false)]
        public string AppEnglishName { get; set; }

        /// <summary>
        /// 小程序应用名称
        /// </summary>
        /// <value>小程序应用名称</value>
        [DataMember(Name = "app_name", EmitDefaultValue = false)]
        public string AppName { get; set; }

        /// <summary>
        /// 来源的业务方，需要申请
        /// </summary>
        /// <value>来源的业务方，需要申请</value>
        [DataMember(Name = "app_origin", EmitDefaultValue = false)]
        public string AppOrigin { get; set; }

        /// <summary>
        /// 小程序应用简介，一句话描述小程序功能
        /// </summary>
        /// <value>小程序应用简介，一句话描述小程序功能</value>
        [DataMember(Name = "app_slogan", EmitDefaultValue = false)]
        public string AppSlogan { get; set; }

        /// <summary>
        /// 订购的服务商品ID所在的市场编码。新接入场景必须传递，具体值请联系产品分配。
        /// </summary>
        /// <value>订购的服务商品ID所在的市场编码。新接入场景必须传递，具体值请联系产品分配。</value>
        [DataMember(Name = "market_code", EmitDefaultValue = false)]
        public string MarketCode { get; set; }

        /// <summary>
        /// 订购的服务商品ID
        /// </summary>
        /// <value>订购的服务商品ID</value>
        [DataMember(Name = "merchandise_id", EmitDefaultValue = false)]
        public string MerchandiseId { get; set; }

        /// <summary>
        /// 商户PID
        /// </summary>
        /// <value>商户PID</value>
        [DataMember(Name = "merchant_pid", EmitDefaultValue = false)]
        public string MerchantPid { get; set; }

        /// <summary>
        /// 一二方支持传入appId
        /// </summary>
        /// <value>一二方支持传入appId</value>
        [DataMember(Name = "mini_app_id", EmitDefaultValue = false)]
        public string MiniAppId { get; set; }

        /// <summary>
        /// 新小程序前台类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目_第二个三级类目，详细类目可以通过 https://docs.open.alipay.com/api_49/alipay.open.mini.category.query接口查询mini_category_list，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。使用后不再读取app_category_ids值，老前台类目将废弃
        /// </summary>
        /// <value>新小程序前台类目，格式为 第一个一级类目_第一个二级类目;第二个一级类目_第二个二级类目_第二个三级类目，详细类目可以通过 https://docs.open.alipay.com/api_49/alipay.open.mini.category.query接口查询mini_category_list，如果不填默认采用当前小程序应用类目。使用默认应用类目后不需要再次上传营业执照号、营业执照名、营业执照截图、营业执照有效期。使用后不再读取app_category_ids值，老前台类目将废弃</value>
        [DataMember(Name = "mini_category_ids", EmitDefaultValue = false)]
        public string MiniCategoryIds { get; set; }

        /// <summary>
        /// 比如某种业务标准外部订单号,比如交易外部订单号，代表商户端自己订单号
        /// </summary>
        /// <value>比如某种业务标准外部订单号,比如交易外部订单号，代表商户端自己订单号</value>
        [DataMember(Name = "out_biz_no", EmitDefaultValue = false)]
        public string OutBizNo { get; set; }

        /// <summary>
        /// 小程序客服邮箱
        /// </summary>
        /// <value>小程序客服邮箱</value>
        [DataMember(Name = "service_email", EmitDefaultValue = false)]
        public string ServiceEmail { get; set; }

        /// <summary>
        /// 小程序客服电话
        /// </summary>
        /// <value>小程序客服电话</value>
        [DataMember(Name = "service_phone", EmitDefaultValue = false)]
        public string ServicePhone { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenServicemarketOrderCreateModel {\n");
            sb.Append("  AppCategoryIds: ").Append(AppCategoryIds).Append("\n");
            sb.Append("  AppDesc: ").Append(AppDesc).Append("\n");
            sb.Append("  AppEnglishName: ").Append(AppEnglishName).Append("\n");
            sb.Append("  AppName: ").Append(AppName).Append("\n");
            sb.Append("  AppOrigin: ").Append(AppOrigin).Append("\n");
            sb.Append("  AppSlogan: ").Append(AppSlogan).Append("\n");
            sb.Append("  MarketCode: ").Append(MarketCode).Append("\n");
            sb.Append("  MerchandiseId: ").Append(MerchandiseId).Append("\n");
            sb.Append("  MerchantPid: ").Append(MerchantPid).Append("\n");
            sb.Append("  MiniAppId: ").Append(MiniAppId).Append("\n");
            sb.Append("  MiniCategoryIds: ").Append(MiniCategoryIds).Append("\n");
            sb.Append("  OutBizNo: ").Append(OutBizNo).Append("\n");
            sb.Append("  ServiceEmail: ").Append(ServiceEmail).Append("\n");
            sb.Append("  ServicePhone: ").Append(ServicePhone).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as AlipayOpenServicemarketOrderCreateModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenServicemarketOrderCreateModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenServicemarketOrderCreateModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenServicemarketOrderCreateModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AppCategoryIds == input.AppCategoryIds ||
                    (this.AppCategoryIds != null &&
                    this.AppCategoryIds.Equals(input.AppCategoryIds))
                ) && 
                (
                    this.AppDesc == input.AppDesc ||
                    (this.AppDesc != null &&
                    this.AppDesc.Equals(input.AppDesc))
                ) && 
                (
                    this.AppEnglishName == input.AppEnglishName ||
                    (this.AppEnglishName != null &&
                    this.AppEnglishName.Equals(input.AppEnglishName))
                ) && 
                (
                    this.AppName == input.AppName ||
                    (this.AppName != null &&
                    this.AppName.Equals(input.AppName))
                ) && 
                (
                    this.AppOrigin == input.AppOrigin ||
                    (this.AppOrigin != null &&
                    this.AppOrigin.Equals(input.AppOrigin))
                ) && 
                (
                    this.AppSlogan == input.AppSlogan ||
                    (this.AppSlogan != null &&
                    this.AppSlogan.Equals(input.AppSlogan))
                ) && 
                (
                    this.MarketCode == input.MarketCode ||
                    (this.MarketCode != null &&
                    this.MarketCode.Equals(input.MarketCode))
                ) && 
                (
                    this.MerchandiseId == input.MerchandiseId ||
                    (this.MerchandiseId != null &&
                    this.MerchandiseId.Equals(input.MerchandiseId))
                ) && 
                (
                    this.MerchantPid == input.MerchantPid ||
                    (this.MerchantPid != null &&
                    this.MerchantPid.Equals(input.MerchantPid))
                ) && 
                (
                    this.MiniAppId == input.MiniAppId ||
                    (this.MiniAppId != null &&
                    this.MiniAppId.Equals(input.MiniAppId))
                ) && 
                (
                    this.MiniCategoryIds == input.MiniCategoryIds ||
                    (this.MiniCategoryIds != null &&
                    this.MiniCategoryIds.Equals(input.MiniCategoryIds))
                ) && 
                (
                    this.OutBizNo == input.OutBizNo ||
                    (this.OutBizNo != null &&
                    this.OutBizNo.Equals(input.OutBizNo))
                ) && 
                (
                    this.ServiceEmail == input.ServiceEmail ||
                    (this.ServiceEmail != null &&
                    this.ServiceEmail.Equals(input.ServiceEmail))
                ) && 
                (
                    this.ServicePhone == input.ServicePhone ||
                    (this.ServicePhone != null &&
                    this.ServicePhone.Equals(input.ServicePhone))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.AppCategoryIds != null)
                {
                    hashCode = (hashCode * 59) + this.AppCategoryIds.GetHashCode();
                }
                if (this.AppDesc != null)
                {
                    hashCode = (hashCode * 59) + this.AppDesc.GetHashCode();
                }
                if (this.AppEnglishName != null)
                {
                    hashCode = (hashCode * 59) + this.AppEnglishName.GetHashCode();
                }
                if (this.AppName != null)
                {
                    hashCode = (hashCode * 59) + this.AppName.GetHashCode();
                }
                if (this.AppOrigin != null)
                {
                    hashCode = (hashCode * 59) + this.AppOrigin.GetHashCode();
                }
                if (this.AppSlogan != null)
                {
                    hashCode = (hashCode * 59) + this.AppSlogan.GetHashCode();
                }
                if (this.MarketCode != null)
                {
                    hashCode = (hashCode * 59) + this.MarketCode.GetHashCode();
                }
                if (this.MerchandiseId != null)
                {
                    hashCode = (hashCode * 59) + this.MerchandiseId.GetHashCode();
                }
                if (this.MerchantPid != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantPid.GetHashCode();
                }
                if (this.MiniAppId != null)
                {
                    hashCode = (hashCode * 59) + this.MiniAppId.GetHashCode();
                }
                if (this.MiniCategoryIds != null)
                {
                    hashCode = (hashCode * 59) + this.MiniCategoryIds.GetHashCode();
                }
                if (this.OutBizNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutBizNo.GetHashCode();
                }
                if (this.ServiceEmail != null)
                {
                    hashCode = (hashCode * 59) + this.ServiceEmail.GetHashCode();
                }
                if (this.ServicePhone != null)
                {
                    hashCode = (hashCode * 59) + this.ServicePhone.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
