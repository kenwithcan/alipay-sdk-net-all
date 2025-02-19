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
    /// AlipayEbppInvoiceAuthUnsignModel
    /// </summary>
    [DataContract(Name = "AlipayEbppInvoiceAuthUnsignModel")]
    public partial class AlipayEbppInvoiceAuthUnsignModel : IEquatable<AlipayEbppInvoiceAuthUnsignModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceAuthUnsignModel" /> class.
        /// </summary>
        /// <param name="authorizationType">发票授权类型，可选值：INVOICE_AUTO_SYNC（发票自动回传） INVOICE_TWOWAY_AUTO_SYNC（发票双向自动回传）.</param>
        /// <param name="extendFields">扩展字段，格式为：KEY1&#x3D;VALUE1,KEY2&#x3D;VALUE2,KEY3&#x3D;VALUE3 邮箱地址KEY为EMAIL_ADDRESS.</param>
        /// <param name="mShortName">开票商户品牌简称，与商户入驻时的品牌简称保持一致。.</param>
        /// <param name="openId">支付宝用户userId.</param>
        /// <param name="userId">支付宝用户userId.</param>
        public AlipayEbppInvoiceAuthUnsignModel(string authorizationType = default(string), string extendFields = default(string), string mShortName = default(string), string openId = default(string), string userId = default(string))
        {
            this.AuthorizationType = authorizationType;
            this.ExtendFields = extendFields;
            this.MShortName = mShortName;
            this.OpenId = openId;
            this.UserId = userId;
        }

        /// <summary>
        /// 发票授权类型，可选值：INVOICE_AUTO_SYNC（发票自动回传） INVOICE_TWOWAY_AUTO_SYNC（发票双向自动回传）
        /// </summary>
        /// <value>发票授权类型，可选值：INVOICE_AUTO_SYNC（发票自动回传） INVOICE_TWOWAY_AUTO_SYNC（发票双向自动回传）</value>
        [DataMember(Name = "authorization_type", EmitDefaultValue = false)]
        public string AuthorizationType { get; set; }

        /// <summary>
        /// 扩展字段，格式为：KEY1&#x3D;VALUE1,KEY2&#x3D;VALUE2,KEY3&#x3D;VALUE3 邮箱地址KEY为EMAIL_ADDRESS
        /// </summary>
        /// <value>扩展字段，格式为：KEY1&#x3D;VALUE1,KEY2&#x3D;VALUE2,KEY3&#x3D;VALUE3 邮箱地址KEY为EMAIL_ADDRESS</value>
        [DataMember(Name = "extend_fields", EmitDefaultValue = false)]
        public string ExtendFields { get; set; }

        /// <summary>
        /// 开票商户品牌简称，与商户入驻时的品牌简称保持一致。
        /// </summary>
        /// <value>开票商户品牌简称，与商户入驻时的品牌简称保持一致。</value>
        [DataMember(Name = "m_short_name", EmitDefaultValue = false)]
        public string MShortName { get; set; }

        /// <summary>
        /// 支付宝用户userId
        /// </summary>
        /// <value>支付宝用户userId</value>
        [DataMember(Name = "open_id", EmitDefaultValue = false)]
        public string OpenId { get; set; }

        /// <summary>
        /// 支付宝用户userId
        /// </summary>
        /// <value>支付宝用户userId</value>
        [DataMember(Name = "user_id", EmitDefaultValue = false)]
        public string UserId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEbppInvoiceAuthUnsignModel {\n");
            sb.Append("  AuthorizationType: ").Append(AuthorizationType).Append("\n");
            sb.Append("  ExtendFields: ").Append(ExtendFields).Append("\n");
            sb.Append("  MShortName: ").Append(MShortName).Append("\n");
            sb.Append("  OpenId: ").Append(OpenId).Append("\n");
            sb.Append("  UserId: ").Append(UserId).Append("\n");
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
            return this.Equals(input as AlipayEbppInvoiceAuthUnsignModel);
        }

        /// <summary>
        /// Returns true if AlipayEbppInvoiceAuthUnsignModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEbppInvoiceAuthUnsignModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEbppInvoiceAuthUnsignModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AuthorizationType == input.AuthorizationType ||
                    (this.AuthorizationType != null &&
                    this.AuthorizationType.Equals(input.AuthorizationType))
                ) && 
                (
                    this.ExtendFields == input.ExtendFields ||
                    (this.ExtendFields != null &&
                    this.ExtendFields.Equals(input.ExtendFields))
                ) && 
                (
                    this.MShortName == input.MShortName ||
                    (this.MShortName != null &&
                    this.MShortName.Equals(input.MShortName))
                ) && 
                (
                    this.OpenId == input.OpenId ||
                    (this.OpenId != null &&
                    this.OpenId.Equals(input.OpenId))
                ) && 
                (
                    this.UserId == input.UserId ||
                    (this.UserId != null &&
                    this.UserId.Equals(input.UserId))
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
                if (this.AuthorizationType != null)
                {
                    hashCode = (hashCode * 59) + this.AuthorizationType.GetHashCode();
                }
                if (this.ExtendFields != null)
                {
                    hashCode = (hashCode * 59) + this.ExtendFields.GetHashCode();
                }
                if (this.MShortName != null)
                {
                    hashCode = (hashCode * 59) + this.MShortName.GetHashCode();
                }
                if (this.OpenId != null)
                {
                    hashCode = (hashCode * 59) + this.OpenId.GetHashCode();
                }
                if (this.UserId != null)
                {
                    hashCode = (hashCode * 59) + this.UserId.GetHashCode();
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
