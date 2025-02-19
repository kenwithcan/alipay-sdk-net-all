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
    /// PaidOuterCardManageUrlConfDTO
    /// </summary>
    [DataContract(Name = "PaidOuterCardManageUrlConfDTO")]
    public partial class PaidOuterCardManageUrlConfDTO : IEquatable<PaidOuterCardManageUrlConfDTO>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PaidOuterCardManageUrlConfDTO" /> class.
        /// </summary>
        /// <param name="cycleManageUrl">连续购买管理地址。包括查看当前用户连续购买详情，关闭连续购买等功能.</param>
        /// <param name="downgradeUrl">付费外卡降级地址.</param>
        /// <param name="refundUrl">续费外卡退款地址.</param>
        /// <param name="renewUrl">付费外卡续费地址.</param>
        /// <param name="upgradeUrl">付费外卡升级地址.</param>
        public PaidOuterCardManageUrlConfDTO(string cycleManageUrl = default(string), string downgradeUrl = default(string), string refundUrl = default(string), string renewUrl = default(string), string upgradeUrl = default(string))
        {
            this.CycleManageUrl = cycleManageUrl;
            this.DowngradeUrl = downgradeUrl;
            this.RefundUrl = refundUrl;
            this.RenewUrl = renewUrl;
            this.UpgradeUrl = upgradeUrl;
        }

        /// <summary>
        /// 连续购买管理地址。包括查看当前用户连续购买详情，关闭连续购买等功能
        /// </summary>
        /// <value>连续购买管理地址。包括查看当前用户连续购买详情，关闭连续购买等功能</value>
        [DataMember(Name = "cycle_manage_url", EmitDefaultValue = false)]
        public string CycleManageUrl { get; set; }

        /// <summary>
        /// 付费外卡降级地址
        /// </summary>
        /// <value>付费外卡降级地址</value>
        [DataMember(Name = "downgrade_url", EmitDefaultValue = false)]
        public string DowngradeUrl { get; set; }

        /// <summary>
        /// 续费外卡退款地址
        /// </summary>
        /// <value>续费外卡退款地址</value>
        [DataMember(Name = "refund_url", EmitDefaultValue = false)]
        public string RefundUrl { get; set; }

        /// <summary>
        /// 付费外卡续费地址
        /// </summary>
        /// <value>付费外卡续费地址</value>
        [DataMember(Name = "renew_url", EmitDefaultValue = false)]
        public string RenewUrl { get; set; }

        /// <summary>
        /// 付费外卡升级地址
        /// </summary>
        /// <value>付费外卡升级地址</value>
        [DataMember(Name = "upgrade_url", EmitDefaultValue = false)]
        public string UpgradeUrl { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class PaidOuterCardManageUrlConfDTO {\n");
            sb.Append("  CycleManageUrl: ").Append(CycleManageUrl).Append("\n");
            sb.Append("  DowngradeUrl: ").Append(DowngradeUrl).Append("\n");
            sb.Append("  RefundUrl: ").Append(RefundUrl).Append("\n");
            sb.Append("  RenewUrl: ").Append(RenewUrl).Append("\n");
            sb.Append("  UpgradeUrl: ").Append(UpgradeUrl).Append("\n");
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
            return this.Equals(input as PaidOuterCardManageUrlConfDTO);
        }

        /// <summary>
        /// Returns true if PaidOuterCardManageUrlConfDTO instances are equal
        /// </summary>
        /// <param name="input">Instance of PaidOuterCardManageUrlConfDTO to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PaidOuterCardManageUrlConfDTO input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.CycleManageUrl == input.CycleManageUrl ||
                    (this.CycleManageUrl != null &&
                    this.CycleManageUrl.Equals(input.CycleManageUrl))
                ) && 
                (
                    this.DowngradeUrl == input.DowngradeUrl ||
                    (this.DowngradeUrl != null &&
                    this.DowngradeUrl.Equals(input.DowngradeUrl))
                ) && 
                (
                    this.RefundUrl == input.RefundUrl ||
                    (this.RefundUrl != null &&
                    this.RefundUrl.Equals(input.RefundUrl))
                ) && 
                (
                    this.RenewUrl == input.RenewUrl ||
                    (this.RenewUrl != null &&
                    this.RenewUrl.Equals(input.RenewUrl))
                ) && 
                (
                    this.UpgradeUrl == input.UpgradeUrl ||
                    (this.UpgradeUrl != null &&
                    this.UpgradeUrl.Equals(input.UpgradeUrl))
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
                if (this.CycleManageUrl != null)
                {
                    hashCode = (hashCode * 59) + this.CycleManageUrl.GetHashCode();
                }
                if (this.DowngradeUrl != null)
                {
                    hashCode = (hashCode * 59) + this.DowngradeUrl.GetHashCode();
                }
                if (this.RefundUrl != null)
                {
                    hashCode = (hashCode * 59) + this.RefundUrl.GetHashCode();
                }
                if (this.RenewUrl != null)
                {
                    hashCode = (hashCode * 59) + this.RenewUrl.GetHashCode();
                }
                if (this.UpgradeUrl != null)
                {
                    hashCode = (hashCode * 59) + this.UpgradeUrl.GetHashCode();
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
