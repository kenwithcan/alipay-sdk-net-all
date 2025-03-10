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
    /// ZhimaCreditPayafteruseCreditagreementQueryResponseModel
    /// </summary>
    [DataContract(Name = "ZhimaCreditPayafteruseCreditagreementQueryResponseModel")]
    public partial class ZhimaCreditPayafteruseCreditagreementQueryResponseModel : IEquatable<ZhimaCreditPayafteruseCreditagreementQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCreditPayafteruseCreditagreementQueryResponseModel" /> class.
        /// </summary>
        /// <param name="agreementStatus">开通/授权状态，VALID: 有效，INVALID: 无效.</param>
        /// <param name="alipayUserId">蚂蚁统一会员ID.</param>
        /// <param name="bizTime">开通时间，agreement_status为VALID有效。.</param>
        /// <param name="creditAgreementId">芝麻开通/授权协议号.</param>
        /// <param name="extInfo">该字段只在特殊业务场景下，根据业务方约定返回；一般业务场景下不需要消费该字段.</param>
        /// <param name="openId">开放ID.</param>
        /// <param name="outAgreementNo">商户外部协议号.</param>
        public ZhimaCreditPayafteruseCreditagreementQueryResponseModel(string agreementStatus = default(string), string alipayUserId = default(string), string bizTime = default(string), string creditAgreementId = default(string), string extInfo = default(string), string openId = default(string), string outAgreementNo = default(string))
        {
            this.AgreementStatus = agreementStatus;
            this.AlipayUserId = alipayUserId;
            this.BizTime = bizTime;
            this.CreditAgreementId = creditAgreementId;
            this.ExtInfo = extInfo;
            this.OpenId = openId;
            this.OutAgreementNo = outAgreementNo;
        }

        /// <summary>
        /// 开通/授权状态，VALID: 有效，INVALID: 无效
        /// </summary>
        /// <value>开通/授权状态，VALID: 有效，INVALID: 无效</value>
        [DataMember(Name = "agreement_status", EmitDefaultValue = false)]
        public string AgreementStatus { get; set; }

        /// <summary>
        /// 蚂蚁统一会员ID
        /// </summary>
        /// <value>蚂蚁统一会员ID</value>
        [DataMember(Name = "alipay_user_id", EmitDefaultValue = false)]
        public string AlipayUserId { get; set; }

        /// <summary>
        /// 开通时间，agreement_status为VALID有效。
        /// </summary>
        /// <value>开通时间，agreement_status为VALID有效。</value>
        [DataMember(Name = "biz_time", EmitDefaultValue = false)]
        public string BizTime { get; set; }

        /// <summary>
        /// 芝麻开通/授权协议号
        /// </summary>
        /// <value>芝麻开通/授权协议号</value>
        [DataMember(Name = "credit_agreement_id", EmitDefaultValue = false)]
        public string CreditAgreementId { get; set; }

        /// <summary>
        /// 该字段只在特殊业务场景下，根据业务方约定返回；一般业务场景下不需要消费该字段
        /// </summary>
        /// <value>该字段只在特殊业务场景下，根据业务方约定返回；一般业务场景下不需要消费该字段</value>
        [DataMember(Name = "ext_info", EmitDefaultValue = false)]
        public string ExtInfo { get; set; }

        /// <summary>
        /// 开放ID
        /// </summary>
        /// <value>开放ID</value>
        [DataMember(Name = "open_id", EmitDefaultValue = false)]
        public string OpenId { get; set; }

        /// <summary>
        /// 商户外部协议号
        /// </summary>
        /// <value>商户外部协议号</value>
        [DataMember(Name = "out_agreement_no", EmitDefaultValue = false)]
        public string OutAgreementNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ZhimaCreditPayafteruseCreditagreementQueryResponseModel {\n");
            sb.Append("  AgreementStatus: ").Append(AgreementStatus).Append("\n");
            sb.Append("  AlipayUserId: ").Append(AlipayUserId).Append("\n");
            sb.Append("  BizTime: ").Append(BizTime).Append("\n");
            sb.Append("  CreditAgreementId: ").Append(CreditAgreementId).Append("\n");
            sb.Append("  ExtInfo: ").Append(ExtInfo).Append("\n");
            sb.Append("  OpenId: ").Append(OpenId).Append("\n");
            sb.Append("  OutAgreementNo: ").Append(OutAgreementNo).Append("\n");
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
            return this.Equals(input as ZhimaCreditPayafteruseCreditagreementQueryResponseModel);
        }

        /// <summary>
        /// Returns true if ZhimaCreditPayafteruseCreditagreementQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of ZhimaCreditPayafteruseCreditagreementQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ZhimaCreditPayafteruseCreditagreementQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AgreementStatus == input.AgreementStatus ||
                    (this.AgreementStatus != null &&
                    this.AgreementStatus.Equals(input.AgreementStatus))
                ) && 
                (
                    this.AlipayUserId == input.AlipayUserId ||
                    (this.AlipayUserId != null &&
                    this.AlipayUserId.Equals(input.AlipayUserId))
                ) && 
                (
                    this.BizTime == input.BizTime ||
                    (this.BizTime != null &&
                    this.BizTime.Equals(input.BizTime))
                ) && 
                (
                    this.CreditAgreementId == input.CreditAgreementId ||
                    (this.CreditAgreementId != null &&
                    this.CreditAgreementId.Equals(input.CreditAgreementId))
                ) && 
                (
                    this.ExtInfo == input.ExtInfo ||
                    (this.ExtInfo != null &&
                    this.ExtInfo.Equals(input.ExtInfo))
                ) && 
                (
                    this.OpenId == input.OpenId ||
                    (this.OpenId != null &&
                    this.OpenId.Equals(input.OpenId))
                ) && 
                (
                    this.OutAgreementNo == input.OutAgreementNo ||
                    (this.OutAgreementNo != null &&
                    this.OutAgreementNo.Equals(input.OutAgreementNo))
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
                if (this.AgreementStatus != null)
                {
                    hashCode = (hashCode * 59) + this.AgreementStatus.GetHashCode();
                }
                if (this.AlipayUserId != null)
                {
                    hashCode = (hashCode * 59) + this.AlipayUserId.GetHashCode();
                }
                if (this.BizTime != null)
                {
                    hashCode = (hashCode * 59) + this.BizTime.GetHashCode();
                }
                if (this.CreditAgreementId != null)
                {
                    hashCode = (hashCode * 59) + this.CreditAgreementId.GetHashCode();
                }
                if (this.ExtInfo != null)
                {
                    hashCode = (hashCode * 59) + this.ExtInfo.GetHashCode();
                }
                if (this.OpenId != null)
                {
                    hashCode = (hashCode * 59) + this.OpenId.GetHashCode();
                }
                if (this.OutAgreementNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutAgreementNo.GetHashCode();
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
