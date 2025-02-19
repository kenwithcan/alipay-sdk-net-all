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
    /// AlipayMarketingCardActivateformQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingCardActivateformQueryResponseModel")]
    public partial class AlipayMarketingCardActivateformQueryResponseModel : IEquatable<AlipayMarketingCardActivateformQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingCardActivateformQueryResponseModel" /> class.
        /// </summary>
        /// <param name="infos">表单提交信息各个字段的值JSON数组    通用表单字段名称如下示例：  OPEN_FORM_FIELD_MOBILE – 手机号  OPEN_FORM_FIELD_GENDER – 性别  OPEN_FORM_FIELD_NAME – 姓名  OPEN_FORM_FIELD_BIRTHDAY – 生日  OPEN_FORM_FIELD_IDCARD – 身份证  OPEN_FORM_FIELD_EMAIL – 邮箱  OPEN_FORM_FIELD_ADDRESS – 地址    详细字段名称列表见会员卡开卡表单模板配置接口：alipay.marketing.card.formtemplate.set    注：  1. 证件类型字段(OPEN_FORM_FIELD_CERT_TYPE)返回结果取值如下:      0 - - 身份证      1 - - 护照      2 - - 港澳居民通行证      3 - - 台湾居民通行证.</param>
        public AlipayMarketingCardActivateformQueryResponseModel(string infos = default(string))
        {
            this.Infos = infos;
        }

        /// <summary>
        /// 表单提交信息各个字段的值JSON数组    通用表单字段名称如下示例：  OPEN_FORM_FIELD_MOBILE – 手机号  OPEN_FORM_FIELD_GENDER – 性别  OPEN_FORM_FIELD_NAME – 姓名  OPEN_FORM_FIELD_BIRTHDAY – 生日  OPEN_FORM_FIELD_IDCARD – 身份证  OPEN_FORM_FIELD_EMAIL – 邮箱  OPEN_FORM_FIELD_ADDRESS – 地址    详细字段名称列表见会员卡开卡表单模板配置接口：alipay.marketing.card.formtemplate.set    注：  1. 证件类型字段(OPEN_FORM_FIELD_CERT_TYPE)返回结果取值如下:      0 - - 身份证      1 - - 护照      2 - - 港澳居民通行证      3 - - 台湾居民通行证
        /// </summary>
        /// <value>表单提交信息各个字段的值JSON数组    通用表单字段名称如下示例：  OPEN_FORM_FIELD_MOBILE – 手机号  OPEN_FORM_FIELD_GENDER – 性别  OPEN_FORM_FIELD_NAME – 姓名  OPEN_FORM_FIELD_BIRTHDAY – 生日  OPEN_FORM_FIELD_IDCARD – 身份证  OPEN_FORM_FIELD_EMAIL – 邮箱  OPEN_FORM_FIELD_ADDRESS – 地址    详细字段名称列表见会员卡开卡表单模板配置接口：alipay.marketing.card.formtemplate.set    注：  1. 证件类型字段(OPEN_FORM_FIELD_CERT_TYPE)返回结果取值如下:      0 - - 身份证      1 - - 护照      2 - - 港澳居民通行证      3 - - 台湾居民通行证</value>
        [DataMember(Name = "infos", EmitDefaultValue = false)]
        public string Infos { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMarketingCardActivateformQueryResponseModel {\n");
            sb.Append("  Infos: ").Append(Infos).Append("\n");
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
            return this.Equals(input as AlipayMarketingCardActivateformQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingCardActivateformQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingCardActivateformQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingCardActivateformQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Infos == input.Infos ||
                    (this.Infos != null &&
                    this.Infos.Equals(input.Infos))
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
                if (this.Infos != null)
                {
                    hashCode = (hashCode * 59) + this.Infos.GetHashCode();
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
