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
    /// AlipayUserTwostageIndirectUseModel
    /// </summary>
    [DataContract(Name = "AlipayUserTwostageIndirectUseModel")]
    public partial class AlipayUserTwostageIndirectUseModel : IEquatable<AlipayUserTwostageIndirectUseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayUserTwostageIndirectUseModel" /> class.
        /// </summary>
        /// <param name="dynamicId">商户扫描用户的付款码值。18~24位，25~30开头，例如28开头的18位的数字；或人脸支付的ftoken等。.</param>
        /// <param name="orgPid">进件信息中，SMID对应的银行机构的PID信息，一般为2088开头的16位数字。.</param>
        /// <param name="paySmid">进件信息中，二级商户ID（ sub_merchant_id)信息，一般为2088开头的16位数字。.</param>
        /// <param name="senceNo">外部业务号，用于标识这笔解码请求，对同一个码的重复解码请求，sence_no必须与上一次保持一致，每次请求的sence_no必须不一样，如alipay.user.twostage.common.use接口配合alipay.trade.pay（统一收单交易支付接口）一并使用时，alipay.trade.pay接口的extend_params属性中必须设置DYNAMIC_TOKEN_OUT_BIZ_NO，且值必须与sence_no保持一致.</param>
        /// <param name="sourcePid">进件信息中，SMID对应渠道的PID信息，一般为2088开头的16位数字。.</param>
        public AlipayUserTwostageIndirectUseModel(string dynamicId = default(string), string orgPid = default(string), string paySmid = default(string), string senceNo = default(string), string sourcePid = default(string))
        {
            this.DynamicId = dynamicId;
            this.OrgPid = orgPid;
            this.PaySmid = paySmid;
            this.SenceNo = senceNo;
            this.SourcePid = sourcePid;
        }

        /// <summary>
        /// 商户扫描用户的付款码值。18~24位，25~30开头，例如28开头的18位的数字；或人脸支付的ftoken等。
        /// </summary>
        /// <value>商户扫描用户的付款码值。18~24位，25~30开头，例如28开头的18位的数字；或人脸支付的ftoken等。</value>
        [DataMember(Name = "dynamic_id", EmitDefaultValue = false)]
        public string DynamicId { get; set; }

        /// <summary>
        /// 进件信息中，SMID对应的银行机构的PID信息，一般为2088开头的16位数字。
        /// </summary>
        /// <value>进件信息中，SMID对应的银行机构的PID信息，一般为2088开头的16位数字。</value>
        [DataMember(Name = "org_pid", EmitDefaultValue = false)]
        public string OrgPid { get; set; }

        /// <summary>
        /// 进件信息中，二级商户ID（ sub_merchant_id)信息，一般为2088开头的16位数字。
        /// </summary>
        /// <value>进件信息中，二级商户ID（ sub_merchant_id)信息，一般为2088开头的16位数字。</value>
        [DataMember(Name = "pay_smid", EmitDefaultValue = false)]
        public string PaySmid { get; set; }

        /// <summary>
        /// 外部业务号，用于标识这笔解码请求，对同一个码的重复解码请求，sence_no必须与上一次保持一致，每次请求的sence_no必须不一样，如alipay.user.twostage.common.use接口配合alipay.trade.pay（统一收单交易支付接口）一并使用时，alipay.trade.pay接口的extend_params属性中必须设置DYNAMIC_TOKEN_OUT_BIZ_NO，且值必须与sence_no保持一致
        /// </summary>
        /// <value>外部业务号，用于标识这笔解码请求，对同一个码的重复解码请求，sence_no必须与上一次保持一致，每次请求的sence_no必须不一样，如alipay.user.twostage.common.use接口配合alipay.trade.pay（统一收单交易支付接口）一并使用时，alipay.trade.pay接口的extend_params属性中必须设置DYNAMIC_TOKEN_OUT_BIZ_NO，且值必须与sence_no保持一致</value>
        [DataMember(Name = "sence_no", EmitDefaultValue = false)]
        public string SenceNo { get; set; }

        /// <summary>
        /// 进件信息中，SMID对应渠道的PID信息，一般为2088开头的16位数字。
        /// </summary>
        /// <value>进件信息中，SMID对应渠道的PID信息，一般为2088开头的16位数字。</value>
        [DataMember(Name = "source_pid", EmitDefaultValue = false)]
        public string SourcePid { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayUserTwostageIndirectUseModel {\n");
            sb.Append("  DynamicId: ").Append(DynamicId).Append("\n");
            sb.Append("  OrgPid: ").Append(OrgPid).Append("\n");
            sb.Append("  PaySmid: ").Append(PaySmid).Append("\n");
            sb.Append("  SenceNo: ").Append(SenceNo).Append("\n");
            sb.Append("  SourcePid: ").Append(SourcePid).Append("\n");
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
            return this.Equals(input as AlipayUserTwostageIndirectUseModel);
        }

        /// <summary>
        /// Returns true if AlipayUserTwostageIndirectUseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayUserTwostageIndirectUseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayUserTwostageIndirectUseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.DynamicId == input.DynamicId ||
                    (this.DynamicId != null &&
                    this.DynamicId.Equals(input.DynamicId))
                ) && 
                (
                    this.OrgPid == input.OrgPid ||
                    (this.OrgPid != null &&
                    this.OrgPid.Equals(input.OrgPid))
                ) && 
                (
                    this.PaySmid == input.PaySmid ||
                    (this.PaySmid != null &&
                    this.PaySmid.Equals(input.PaySmid))
                ) && 
                (
                    this.SenceNo == input.SenceNo ||
                    (this.SenceNo != null &&
                    this.SenceNo.Equals(input.SenceNo))
                ) && 
                (
                    this.SourcePid == input.SourcePid ||
                    (this.SourcePid != null &&
                    this.SourcePid.Equals(input.SourcePid))
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
                if (this.DynamicId != null)
                {
                    hashCode = (hashCode * 59) + this.DynamicId.GetHashCode();
                }
                if (this.OrgPid != null)
                {
                    hashCode = (hashCode * 59) + this.OrgPid.GetHashCode();
                }
                if (this.PaySmid != null)
                {
                    hashCode = (hashCode * 59) + this.PaySmid.GetHashCode();
                }
                if (this.SenceNo != null)
                {
                    hashCode = (hashCode * 59) + this.SenceNo.GetHashCode();
                }
                if (this.SourcePid != null)
                {
                    hashCode = (hashCode * 59) + this.SourcePid.GetHashCode();
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
