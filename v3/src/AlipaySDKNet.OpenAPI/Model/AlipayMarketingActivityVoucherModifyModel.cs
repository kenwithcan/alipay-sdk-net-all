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
    /// AlipayMarketingActivityVoucherModifyModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingActivityVoucherModifyModel")]
    public partial class AlipayMarketingActivityVoucherModifyModel : IEquatable<AlipayMarketingActivityVoucherModifyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityVoucherModifyModel" /> class.
        /// </summary>
        /// <param name="activityBaseInfo">activityBaseInfo.</param>
        /// <param name="activityId">活动id.</param>
        /// <param name="merchantAccessMode">商户接入模式.</param>
        /// <param name="outBizNo">外部业务单号，用作幂等控制。 幂等作用： 参数不变的情况下，再次请求返回与上一次相同的结果。.</param>
        /// <param name="publishEndTime">券发放结束时间。格式为：yyyy-MM-dd HH:mm:ss.</param>
        /// <param name="voucherAvailableScopeInfo">voucherAvailableScopeInfo.</param>
        /// <param name="voucherSendModeInfo">voucherSendModeInfo.</param>
        /// <param name="voucherUseRule">voucherUseRule.</param>
        /// <param name="voucherUseRuleInfo">voucherUseRuleInfo.</param>
        public AlipayMarketingActivityVoucherModifyModel(ActivityBaseInfo activityBaseInfo = default(ActivityBaseInfo), string activityId = default(string), string merchantAccessMode = default(string), string outBizNo = default(string), string publishEndTime = default(string), VoucherAvailableScopeInfo voucherAvailableScopeInfo = default(VoucherAvailableScopeInfo), VoucherSendModeInfo voucherSendModeInfo = default(VoucherSendModeInfo), PaymentVoucherUseRuleModify voucherUseRule = default(PaymentVoucherUseRuleModify), VoucherUseRuleInfo voucherUseRuleInfo = default(VoucherUseRuleInfo))
        {
            this.ActivityBaseInfo = activityBaseInfo;
            this.ActivityId = activityId;
            this.MerchantAccessMode = merchantAccessMode;
            this.OutBizNo = outBizNo;
            this.PublishEndTime = publishEndTime;
            this.VoucherAvailableScopeInfo = voucherAvailableScopeInfo;
            this.VoucherSendModeInfo = voucherSendModeInfo;
            this.VoucherUseRule = voucherUseRule;
            this.VoucherUseRuleInfo = voucherUseRuleInfo;
        }

        /// <summary>
        /// Gets or Sets ActivityBaseInfo
        /// </summary>
        [DataMember(Name = "activity_base_info", EmitDefaultValue = false)]
        public ActivityBaseInfo ActivityBaseInfo { get; set; }

        /// <summary>
        /// 活动id
        /// </summary>
        /// <value>活动id</value>
        [DataMember(Name = "activity_id", EmitDefaultValue = false)]
        public string ActivityId { get; set; }

        /// <summary>
        /// 商户接入模式
        /// </summary>
        /// <value>商户接入模式</value>
        [DataMember(Name = "merchant_access_mode", EmitDefaultValue = false)]
        public string MerchantAccessMode { get; set; }

        /// <summary>
        /// 外部业务单号，用作幂等控制。 幂等作用： 参数不变的情况下，再次请求返回与上一次相同的结果。
        /// </summary>
        /// <value>外部业务单号，用作幂等控制。 幂等作用： 参数不变的情况下，再次请求返回与上一次相同的结果。</value>
        [DataMember(Name = "out_biz_no", EmitDefaultValue = false)]
        public string OutBizNo { get; set; }

        /// <summary>
        /// 券发放结束时间。格式为：yyyy-MM-dd HH:mm:ss
        /// </summary>
        /// <value>券发放结束时间。格式为：yyyy-MM-dd HH:mm:ss</value>
        [DataMember(Name = "publish_end_time", EmitDefaultValue = false)]
        public string PublishEndTime { get; set; }

        /// <summary>
        /// Gets or Sets VoucherAvailableScopeInfo
        /// </summary>
        [DataMember(Name = "voucher_available_scope_info", EmitDefaultValue = false)]
        public VoucherAvailableScopeInfo VoucherAvailableScopeInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherSendModeInfo
        /// </summary>
        [DataMember(Name = "voucher_send_mode_info", EmitDefaultValue = false)]
        public VoucherSendModeInfo VoucherSendModeInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherUseRule
        /// </summary>
        [DataMember(Name = "voucher_use_rule", EmitDefaultValue = false)]
        public PaymentVoucherUseRuleModify VoucherUseRule { get; set; }

        /// <summary>
        /// Gets or Sets VoucherUseRuleInfo
        /// </summary>
        [DataMember(Name = "voucher_use_rule_info", EmitDefaultValue = false)]
        public VoucherUseRuleInfo VoucherUseRuleInfo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMarketingActivityVoucherModifyModel {\n");
            sb.Append("  ActivityBaseInfo: ").Append(ActivityBaseInfo).Append("\n");
            sb.Append("  ActivityId: ").Append(ActivityId).Append("\n");
            sb.Append("  MerchantAccessMode: ").Append(MerchantAccessMode).Append("\n");
            sb.Append("  OutBizNo: ").Append(OutBizNo).Append("\n");
            sb.Append("  PublishEndTime: ").Append(PublishEndTime).Append("\n");
            sb.Append("  VoucherAvailableScopeInfo: ").Append(VoucherAvailableScopeInfo).Append("\n");
            sb.Append("  VoucherSendModeInfo: ").Append(VoucherSendModeInfo).Append("\n");
            sb.Append("  VoucherUseRule: ").Append(VoucherUseRule).Append("\n");
            sb.Append("  VoucherUseRuleInfo: ").Append(VoucherUseRuleInfo).Append("\n");
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
            return this.Equals(input as AlipayMarketingActivityVoucherModifyModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingActivityVoucherModifyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingActivityVoucherModifyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingActivityVoucherModifyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ActivityBaseInfo == input.ActivityBaseInfo ||
                    (this.ActivityBaseInfo != null &&
                    this.ActivityBaseInfo.Equals(input.ActivityBaseInfo))
                ) && 
                (
                    this.ActivityId == input.ActivityId ||
                    (this.ActivityId != null &&
                    this.ActivityId.Equals(input.ActivityId))
                ) && 
                (
                    this.MerchantAccessMode == input.MerchantAccessMode ||
                    (this.MerchantAccessMode != null &&
                    this.MerchantAccessMode.Equals(input.MerchantAccessMode))
                ) && 
                (
                    this.OutBizNo == input.OutBizNo ||
                    (this.OutBizNo != null &&
                    this.OutBizNo.Equals(input.OutBizNo))
                ) && 
                (
                    this.PublishEndTime == input.PublishEndTime ||
                    (this.PublishEndTime != null &&
                    this.PublishEndTime.Equals(input.PublishEndTime))
                ) && 
                (
                    this.VoucherAvailableScopeInfo == input.VoucherAvailableScopeInfo ||
                    (this.VoucherAvailableScopeInfo != null &&
                    this.VoucherAvailableScopeInfo.Equals(input.VoucherAvailableScopeInfo))
                ) && 
                (
                    this.VoucherSendModeInfo == input.VoucherSendModeInfo ||
                    (this.VoucherSendModeInfo != null &&
                    this.VoucherSendModeInfo.Equals(input.VoucherSendModeInfo))
                ) && 
                (
                    this.VoucherUseRule == input.VoucherUseRule ||
                    (this.VoucherUseRule != null &&
                    this.VoucherUseRule.Equals(input.VoucherUseRule))
                ) && 
                (
                    this.VoucherUseRuleInfo == input.VoucherUseRuleInfo ||
                    (this.VoucherUseRuleInfo != null &&
                    this.VoucherUseRuleInfo.Equals(input.VoucherUseRuleInfo))
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
                if (this.ActivityBaseInfo != null)
                {
                    hashCode = (hashCode * 59) + this.ActivityBaseInfo.GetHashCode();
                }
                if (this.ActivityId != null)
                {
                    hashCode = (hashCode * 59) + this.ActivityId.GetHashCode();
                }
                if (this.MerchantAccessMode != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantAccessMode.GetHashCode();
                }
                if (this.OutBizNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutBizNo.GetHashCode();
                }
                if (this.PublishEndTime != null)
                {
                    hashCode = (hashCode * 59) + this.PublishEndTime.GetHashCode();
                }
                if (this.VoucherAvailableScopeInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherAvailableScopeInfo.GetHashCode();
                }
                if (this.VoucherSendModeInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherSendModeInfo.GetHashCode();
                }
                if (this.VoucherUseRule != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherUseRule.GetHashCode();
                }
                if (this.VoucherUseRuleInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherUseRuleInfo.GetHashCode();
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
