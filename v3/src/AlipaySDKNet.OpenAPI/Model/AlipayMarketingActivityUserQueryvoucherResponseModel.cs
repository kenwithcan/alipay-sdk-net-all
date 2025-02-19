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
    /// AlipayMarketingActivityUserQueryvoucherResponseModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingActivityUserQueryvoucherResponseModel")]
    public partial class AlipayMarketingActivityUserQueryvoucherResponseModel : IEquatable<AlipayMarketingActivityUserQueryvoucherResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityUserQueryvoucherResponseModel" /> class.
        /// </summary>
        /// <param name="activityBaseInfo">activityBaseInfo.</param>
        /// <param name="activityId">活动 id.</param>
        /// <param name="associateTradeNo">若商家券操作过关联商户订单信息，则该字段返回商家券已关联的商户订单号。.</param>
        /// <param name="availableBeginTime">券可用开始时间。格式为：yyyy-MM-dd HH:mm:ss.</param>
        /// <param name="availableEndTime">券可用结束时间。格式为：yyyy-MM-dd HH:mm:ss.</param>
        /// <param name="belongMerchantId">券归属 pid.</param>
        /// <param name="createTime">领券时间.</param>
        /// <param name="userVoucherBaseInfo">userVoucherBaseInfo.</param>
        /// <param name="voucherCustomerGuideInfo">voucherCustomerGuideInfo.</param>
        /// <param name="voucherDeductInfo">voucherDeductInfo.</param>
        /// <param name="voucherDisplayInfo">voucherDisplayInfo.</param>
        /// <param name="voucherDisplayPatternInfo">voucherDisplayPatternInfo.</param>
        /// <param name="voucherName">对消费者展示的券(商品)名称。.</param>
        /// <param name="voucherSendModeInfo">voucherSendModeInfo.</param>
        /// <param name="voucherSendRule">voucherSendRule.</param>
        /// <param name="voucherStatus">券状态。.</param>
        /// <param name="voucherType">券类型。.</param>
        /// <param name="voucherUseRule">voucherUseRule.</param>
        /// <param name="voucherUseRuleInfo">voucherUseRuleInfo.</param>
        public AlipayMarketingActivityUserQueryvoucherResponseModel(ActivityBaseInfo activityBaseInfo = default(ActivityBaseInfo), string activityId = default(string), string associateTradeNo = default(string), string availableBeginTime = default(string), string availableEndTime = default(string), string belongMerchantId = default(string), string createTime = default(string), UserVoucherBaseInfo userVoucherBaseInfo = default(UserVoucherBaseInfo), VoucherCustomerGuideInfo voucherCustomerGuideInfo = default(VoucherCustomerGuideInfo), VoucherDeductInfo voucherDeductInfo = default(VoucherDeductInfo), CommonVoucherDisplayInfo voucherDisplayInfo = default(CommonVoucherDisplayInfo), VoucherDisplayPatternInfo voucherDisplayPatternInfo = default(VoucherDisplayPatternInfo), string voucherName = default(string), VoucherSendModeInfo voucherSendModeInfo = default(VoucherSendModeInfo), CommonVoucherSendRule voucherSendRule = default(CommonVoucherSendRule), string voucherStatus = default(string), string voucherType = default(string), CommonVoucherUseRule voucherUseRule = default(CommonVoucherUseRule), VoucherUseRuleInfo voucherUseRuleInfo = default(VoucherUseRuleInfo))
        {
            this.ActivityBaseInfo = activityBaseInfo;
            this.ActivityId = activityId;
            this.AssociateTradeNo = associateTradeNo;
            this.AvailableBeginTime = availableBeginTime;
            this.AvailableEndTime = availableEndTime;
            this.BelongMerchantId = belongMerchantId;
            this.CreateTime = createTime;
            this.UserVoucherBaseInfo = userVoucherBaseInfo;
            this.VoucherCustomerGuideInfo = voucherCustomerGuideInfo;
            this.VoucherDeductInfo = voucherDeductInfo;
            this.VoucherDisplayInfo = voucherDisplayInfo;
            this.VoucherDisplayPatternInfo = voucherDisplayPatternInfo;
            this.VoucherName = voucherName;
            this.VoucherSendModeInfo = voucherSendModeInfo;
            this.VoucherSendRule = voucherSendRule;
            this.VoucherStatus = voucherStatus;
            this.VoucherType = voucherType;
            this.VoucherUseRule = voucherUseRule;
            this.VoucherUseRuleInfo = voucherUseRuleInfo;
        }

        /// <summary>
        /// Gets or Sets ActivityBaseInfo
        /// </summary>
        [DataMember(Name = "activity_base_info", EmitDefaultValue = false)]
        public ActivityBaseInfo ActivityBaseInfo { get; set; }

        /// <summary>
        /// 活动 id
        /// </summary>
        /// <value>活动 id</value>
        [DataMember(Name = "activity_id", EmitDefaultValue = false)]
        public string ActivityId { get; set; }

        /// <summary>
        /// 若商家券操作过关联商户订单信息，则该字段返回商家券已关联的商户订单号。
        /// </summary>
        /// <value>若商家券操作过关联商户订单信息，则该字段返回商家券已关联的商户订单号。</value>
        [DataMember(Name = "associate_trade_no", EmitDefaultValue = false)]
        public string AssociateTradeNo { get; set; }

        /// <summary>
        /// 券可用开始时间。格式为：yyyy-MM-dd HH:mm:ss
        /// </summary>
        /// <value>券可用开始时间。格式为：yyyy-MM-dd HH:mm:ss</value>
        [DataMember(Name = "available_begin_time", EmitDefaultValue = false)]
        public string AvailableBeginTime { get; set; }

        /// <summary>
        /// 券可用结束时间。格式为：yyyy-MM-dd HH:mm:ss
        /// </summary>
        /// <value>券可用结束时间。格式为：yyyy-MM-dd HH:mm:ss</value>
        [DataMember(Name = "available_end_time", EmitDefaultValue = false)]
        public string AvailableEndTime { get; set; }

        /// <summary>
        /// 券归属 pid
        /// </summary>
        /// <value>券归属 pid</value>
        [DataMember(Name = "belong_merchant_id", EmitDefaultValue = false)]
        public string BelongMerchantId { get; set; }

        /// <summary>
        /// 领券时间
        /// </summary>
        /// <value>领券时间</value>
        [DataMember(Name = "create_time", EmitDefaultValue = false)]
        public string CreateTime { get; set; }

        /// <summary>
        /// Gets or Sets UserVoucherBaseInfo
        /// </summary>
        [DataMember(Name = "user_voucher_base_info", EmitDefaultValue = false)]
        public UserVoucherBaseInfo UserVoucherBaseInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherCustomerGuideInfo
        /// </summary>
        [DataMember(Name = "voucher_customer_guide_info", EmitDefaultValue = false)]
        public VoucherCustomerGuideInfo VoucherCustomerGuideInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherDeductInfo
        /// </summary>
        [DataMember(Name = "voucher_deduct_info", EmitDefaultValue = false)]
        public VoucherDeductInfo VoucherDeductInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherDisplayInfo
        /// </summary>
        [DataMember(Name = "voucher_display_info", EmitDefaultValue = false)]
        public CommonVoucherDisplayInfo VoucherDisplayInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherDisplayPatternInfo
        /// </summary>
        [DataMember(Name = "voucher_display_pattern_info", EmitDefaultValue = false)]
        public VoucherDisplayPatternInfo VoucherDisplayPatternInfo { get; set; }

        /// <summary>
        /// 对消费者展示的券(商品)名称。
        /// </summary>
        /// <value>对消费者展示的券(商品)名称。</value>
        [DataMember(Name = "voucher_name", EmitDefaultValue = false)]
        public string VoucherName { get; set; }

        /// <summary>
        /// Gets or Sets VoucherSendModeInfo
        /// </summary>
        [DataMember(Name = "voucher_send_mode_info", EmitDefaultValue = false)]
        public VoucherSendModeInfo VoucherSendModeInfo { get; set; }

        /// <summary>
        /// Gets or Sets VoucherSendRule
        /// </summary>
        [DataMember(Name = "voucher_send_rule", EmitDefaultValue = false)]
        public CommonVoucherSendRule VoucherSendRule { get; set; }

        /// <summary>
        /// 券状态。
        /// </summary>
        /// <value>券状态。</value>
        [DataMember(Name = "voucher_status", EmitDefaultValue = false)]
        public string VoucherStatus { get; set; }

        /// <summary>
        /// 券类型。
        /// </summary>
        /// <value>券类型。</value>
        [DataMember(Name = "voucher_type", EmitDefaultValue = false)]
        public string VoucherType { get; set; }

        /// <summary>
        /// Gets or Sets VoucherUseRule
        /// </summary>
        [DataMember(Name = "voucher_use_rule", EmitDefaultValue = false)]
        public CommonVoucherUseRule VoucherUseRule { get; set; }

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
            sb.Append("class AlipayMarketingActivityUserQueryvoucherResponseModel {\n");
            sb.Append("  ActivityBaseInfo: ").Append(ActivityBaseInfo).Append("\n");
            sb.Append("  ActivityId: ").Append(ActivityId).Append("\n");
            sb.Append("  AssociateTradeNo: ").Append(AssociateTradeNo).Append("\n");
            sb.Append("  AvailableBeginTime: ").Append(AvailableBeginTime).Append("\n");
            sb.Append("  AvailableEndTime: ").Append(AvailableEndTime).Append("\n");
            sb.Append("  BelongMerchantId: ").Append(BelongMerchantId).Append("\n");
            sb.Append("  CreateTime: ").Append(CreateTime).Append("\n");
            sb.Append("  UserVoucherBaseInfo: ").Append(UserVoucherBaseInfo).Append("\n");
            sb.Append("  VoucherCustomerGuideInfo: ").Append(VoucherCustomerGuideInfo).Append("\n");
            sb.Append("  VoucherDeductInfo: ").Append(VoucherDeductInfo).Append("\n");
            sb.Append("  VoucherDisplayInfo: ").Append(VoucherDisplayInfo).Append("\n");
            sb.Append("  VoucherDisplayPatternInfo: ").Append(VoucherDisplayPatternInfo).Append("\n");
            sb.Append("  VoucherName: ").Append(VoucherName).Append("\n");
            sb.Append("  VoucherSendModeInfo: ").Append(VoucherSendModeInfo).Append("\n");
            sb.Append("  VoucherSendRule: ").Append(VoucherSendRule).Append("\n");
            sb.Append("  VoucherStatus: ").Append(VoucherStatus).Append("\n");
            sb.Append("  VoucherType: ").Append(VoucherType).Append("\n");
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
            return this.Equals(input as AlipayMarketingActivityUserQueryvoucherResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingActivityUserQueryvoucherResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingActivityUserQueryvoucherResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingActivityUserQueryvoucherResponseModel input)
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
                    this.AssociateTradeNo == input.AssociateTradeNo ||
                    (this.AssociateTradeNo != null &&
                    this.AssociateTradeNo.Equals(input.AssociateTradeNo))
                ) && 
                (
                    this.AvailableBeginTime == input.AvailableBeginTime ||
                    (this.AvailableBeginTime != null &&
                    this.AvailableBeginTime.Equals(input.AvailableBeginTime))
                ) && 
                (
                    this.AvailableEndTime == input.AvailableEndTime ||
                    (this.AvailableEndTime != null &&
                    this.AvailableEndTime.Equals(input.AvailableEndTime))
                ) && 
                (
                    this.BelongMerchantId == input.BelongMerchantId ||
                    (this.BelongMerchantId != null &&
                    this.BelongMerchantId.Equals(input.BelongMerchantId))
                ) && 
                (
                    this.CreateTime == input.CreateTime ||
                    (this.CreateTime != null &&
                    this.CreateTime.Equals(input.CreateTime))
                ) && 
                (
                    this.UserVoucherBaseInfo == input.UserVoucherBaseInfo ||
                    (this.UserVoucherBaseInfo != null &&
                    this.UserVoucherBaseInfo.Equals(input.UserVoucherBaseInfo))
                ) && 
                (
                    this.VoucherCustomerGuideInfo == input.VoucherCustomerGuideInfo ||
                    (this.VoucherCustomerGuideInfo != null &&
                    this.VoucherCustomerGuideInfo.Equals(input.VoucherCustomerGuideInfo))
                ) && 
                (
                    this.VoucherDeductInfo == input.VoucherDeductInfo ||
                    (this.VoucherDeductInfo != null &&
                    this.VoucherDeductInfo.Equals(input.VoucherDeductInfo))
                ) && 
                (
                    this.VoucherDisplayInfo == input.VoucherDisplayInfo ||
                    (this.VoucherDisplayInfo != null &&
                    this.VoucherDisplayInfo.Equals(input.VoucherDisplayInfo))
                ) && 
                (
                    this.VoucherDisplayPatternInfo == input.VoucherDisplayPatternInfo ||
                    (this.VoucherDisplayPatternInfo != null &&
                    this.VoucherDisplayPatternInfo.Equals(input.VoucherDisplayPatternInfo))
                ) && 
                (
                    this.VoucherName == input.VoucherName ||
                    (this.VoucherName != null &&
                    this.VoucherName.Equals(input.VoucherName))
                ) && 
                (
                    this.VoucherSendModeInfo == input.VoucherSendModeInfo ||
                    (this.VoucherSendModeInfo != null &&
                    this.VoucherSendModeInfo.Equals(input.VoucherSendModeInfo))
                ) && 
                (
                    this.VoucherSendRule == input.VoucherSendRule ||
                    (this.VoucherSendRule != null &&
                    this.VoucherSendRule.Equals(input.VoucherSendRule))
                ) && 
                (
                    this.VoucherStatus == input.VoucherStatus ||
                    (this.VoucherStatus != null &&
                    this.VoucherStatus.Equals(input.VoucherStatus))
                ) && 
                (
                    this.VoucherType == input.VoucherType ||
                    (this.VoucherType != null &&
                    this.VoucherType.Equals(input.VoucherType))
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
                if (this.AssociateTradeNo != null)
                {
                    hashCode = (hashCode * 59) + this.AssociateTradeNo.GetHashCode();
                }
                if (this.AvailableBeginTime != null)
                {
                    hashCode = (hashCode * 59) + this.AvailableBeginTime.GetHashCode();
                }
                if (this.AvailableEndTime != null)
                {
                    hashCode = (hashCode * 59) + this.AvailableEndTime.GetHashCode();
                }
                if (this.BelongMerchantId != null)
                {
                    hashCode = (hashCode * 59) + this.BelongMerchantId.GetHashCode();
                }
                if (this.CreateTime != null)
                {
                    hashCode = (hashCode * 59) + this.CreateTime.GetHashCode();
                }
                if (this.UserVoucherBaseInfo != null)
                {
                    hashCode = (hashCode * 59) + this.UserVoucherBaseInfo.GetHashCode();
                }
                if (this.VoucherCustomerGuideInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherCustomerGuideInfo.GetHashCode();
                }
                if (this.VoucherDeductInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherDeductInfo.GetHashCode();
                }
                if (this.VoucherDisplayInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherDisplayInfo.GetHashCode();
                }
                if (this.VoucherDisplayPatternInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherDisplayPatternInfo.GetHashCode();
                }
                if (this.VoucherName != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherName.GetHashCode();
                }
                if (this.VoucherSendModeInfo != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherSendModeInfo.GetHashCode();
                }
                if (this.VoucherSendRule != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherSendRule.GetHashCode();
                }
                if (this.VoucherStatus != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherStatus.GetHashCode();
                }
                if (this.VoucherType != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherType.GetHashCode();
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
