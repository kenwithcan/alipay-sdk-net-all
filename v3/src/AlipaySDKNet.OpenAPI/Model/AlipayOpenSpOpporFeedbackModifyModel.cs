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
    /// AlipayOpenSpOpporFeedbackModifyModel
    /// </summary>
    [DataContract(Name = "AlipayOpenSpOpporFeedbackModifyModel")]
    public partial class AlipayOpenSpOpporFeedbackModifyModel : IEquatable<AlipayOpenSpOpporFeedbackModifyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenSpOpporFeedbackModifyModel" /> class.
        /// </summary>
        /// <param name="expandResult">拓展助手商机拓展结果.</param>
        /// <param name="isvPid">服务商pid.</param>
        /// <param name="leadsId">商机id.</param>
        /// <param name="merchantPid">拓展助手商机商家pid.</param>
        /// <param name="opporId">商机作业id.</param>
        /// <param name="sn">拓展设备sn号.</param>
        public AlipayOpenSpOpporFeedbackModifyModel(string expandResult = default(string), string isvPid = default(string), string leadsId = default(string), string merchantPid = default(string), string opporId = default(string), string sn = default(string))
        {
            this.ExpandResult = expandResult;
            this.IsvPid = isvPid;
            this.LeadsId = leadsId;
            this.MerchantPid = merchantPid;
            this.OpporId = opporId;
            this.Sn = sn;
        }

        /// <summary>
        /// 拓展助手商机拓展结果
        /// </summary>
        /// <value>拓展助手商机拓展结果</value>
        [DataMember(Name = "expand_result", EmitDefaultValue = false)]
        public string ExpandResult { get; set; }

        /// <summary>
        /// 服务商pid
        /// </summary>
        /// <value>服务商pid</value>
        [DataMember(Name = "isv_pid", EmitDefaultValue = false)]
        public string IsvPid { get; set; }

        /// <summary>
        /// 商机id
        /// </summary>
        /// <value>商机id</value>
        [DataMember(Name = "leads_id", EmitDefaultValue = false)]
        public string LeadsId { get; set; }

        /// <summary>
        /// 拓展助手商机商家pid
        /// </summary>
        /// <value>拓展助手商机商家pid</value>
        [DataMember(Name = "merchant_pid", EmitDefaultValue = false)]
        public string MerchantPid { get; set; }

        /// <summary>
        /// 商机作业id
        /// </summary>
        /// <value>商机作业id</value>
        [DataMember(Name = "oppor_id", EmitDefaultValue = false)]
        public string OpporId { get; set; }

        /// <summary>
        /// 拓展设备sn号
        /// </summary>
        /// <value>拓展设备sn号</value>
        [DataMember(Name = "sn", EmitDefaultValue = false)]
        public string Sn { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenSpOpporFeedbackModifyModel {\n");
            sb.Append("  ExpandResult: ").Append(ExpandResult).Append("\n");
            sb.Append("  IsvPid: ").Append(IsvPid).Append("\n");
            sb.Append("  LeadsId: ").Append(LeadsId).Append("\n");
            sb.Append("  MerchantPid: ").Append(MerchantPid).Append("\n");
            sb.Append("  OpporId: ").Append(OpporId).Append("\n");
            sb.Append("  Sn: ").Append(Sn).Append("\n");
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
            return this.Equals(input as AlipayOpenSpOpporFeedbackModifyModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenSpOpporFeedbackModifyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenSpOpporFeedbackModifyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenSpOpporFeedbackModifyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ExpandResult == input.ExpandResult ||
                    (this.ExpandResult != null &&
                    this.ExpandResult.Equals(input.ExpandResult))
                ) && 
                (
                    this.IsvPid == input.IsvPid ||
                    (this.IsvPid != null &&
                    this.IsvPid.Equals(input.IsvPid))
                ) && 
                (
                    this.LeadsId == input.LeadsId ||
                    (this.LeadsId != null &&
                    this.LeadsId.Equals(input.LeadsId))
                ) && 
                (
                    this.MerchantPid == input.MerchantPid ||
                    (this.MerchantPid != null &&
                    this.MerchantPid.Equals(input.MerchantPid))
                ) && 
                (
                    this.OpporId == input.OpporId ||
                    (this.OpporId != null &&
                    this.OpporId.Equals(input.OpporId))
                ) && 
                (
                    this.Sn == input.Sn ||
                    (this.Sn != null &&
                    this.Sn.Equals(input.Sn))
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
                if (this.ExpandResult != null)
                {
                    hashCode = (hashCode * 59) + this.ExpandResult.GetHashCode();
                }
                if (this.IsvPid != null)
                {
                    hashCode = (hashCode * 59) + this.IsvPid.GetHashCode();
                }
                if (this.LeadsId != null)
                {
                    hashCode = (hashCode * 59) + this.LeadsId.GetHashCode();
                }
                if (this.MerchantPid != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantPid.GetHashCode();
                }
                if (this.OpporId != null)
                {
                    hashCode = (hashCode * 59) + this.OpporId.GetHashCode();
                }
                if (this.Sn != null)
                {
                    hashCode = (hashCode * 59) + this.Sn.GetHashCode();
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
