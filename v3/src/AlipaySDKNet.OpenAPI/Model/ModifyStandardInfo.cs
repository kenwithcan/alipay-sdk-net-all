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
    /// ModifyStandardInfo
    /// </summary>
    [DataContract(Name = "ModifyStandardInfo")]
    public partial class ModifyStandardInfo : IEquatable<ModifyStandardInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ModifyStandardInfo" /> class.
        /// </summary>
        /// <param name="addConditionList">要添加的条件列表.</param>
        /// <param name="consumeMode">消费模式.</param>
        /// <param name="deleteConditionIdList">待删除的条件id列表.</param>
        /// <param name="modifyConditionList">修改的条件列表.</param>
        /// <param name="openRuleId">使用规则绑定的开票规则id.</param>
        /// <param name="paymentPolicy">支付策略 当笔消费金额大于规则可用余额时，用于控制支付策略。COMBINATION表示支持因公资产和个人资产组合支付，PERSONAL表示整单个人支付。.</param>
        /// <param name="personalQrcodeMode">个人收款码转账是否支持因公付。可选值：0（不支持）、1（支持）.</param>
        /// <param name="standardDesc">使用规则描述.</param>
        /// <param name="standardId">修改的使用规则id.</param>
        /// <param name="standardName">使用规则名称.</param>
        public ModifyStandardInfo(List<StandardConditionInfo> addConditionList = default(List<StandardConditionInfo>), string consumeMode = default(string), List<string> deleteConditionIdList = default(List<string>), List<StandardConditionInfo> modifyConditionList = default(List<StandardConditionInfo>), string openRuleId = default(string), string paymentPolicy = default(string), int personalQrcodeMode = default(int), string standardDesc = default(string), string standardId = default(string), string standardName = default(string))
        {
            this.AddConditionList = addConditionList;
            this.ConsumeMode = consumeMode;
            this.DeleteConditionIdList = deleteConditionIdList;
            this.ModifyConditionList = modifyConditionList;
            this.OpenRuleId = openRuleId;
            this.PaymentPolicy = paymentPolicy;
            this.PersonalQrcodeMode = personalQrcodeMode;
            this.StandardDesc = standardDesc;
            this.StandardId = standardId;
            this.StandardName = standardName;
        }

        /// <summary>
        /// 要添加的条件列表
        /// </summary>
        /// <value>要添加的条件列表</value>
        [DataMember(Name = "add_condition_list", EmitDefaultValue = false)]
        public List<StandardConditionInfo> AddConditionList { get; set; }

        /// <summary>
        /// 消费模式
        /// </summary>
        /// <value>消费模式</value>
        [DataMember(Name = "consume_mode", EmitDefaultValue = false)]
        public string ConsumeMode { get; set; }

        /// <summary>
        /// 待删除的条件id列表
        /// </summary>
        /// <value>待删除的条件id列表</value>
        [DataMember(Name = "delete_condition_id_list", EmitDefaultValue = false)]
        public List<string> DeleteConditionIdList { get; set; }

        /// <summary>
        /// 修改的条件列表
        /// </summary>
        /// <value>修改的条件列表</value>
        [DataMember(Name = "modify_condition_list", EmitDefaultValue = false)]
        public List<StandardConditionInfo> ModifyConditionList { get; set; }

        /// <summary>
        /// 使用规则绑定的开票规则id
        /// </summary>
        /// <value>使用规则绑定的开票规则id</value>
        [DataMember(Name = "open_rule_id", EmitDefaultValue = false)]
        public string OpenRuleId { get; set; }

        /// <summary>
        /// 支付策略 当笔消费金额大于规则可用余额时，用于控制支付策略。COMBINATION表示支持因公资产和个人资产组合支付，PERSONAL表示整单个人支付。
        /// </summary>
        /// <value>支付策略 当笔消费金额大于规则可用余额时，用于控制支付策略。COMBINATION表示支持因公资产和个人资产组合支付，PERSONAL表示整单个人支付。</value>
        [DataMember(Name = "payment_policy", EmitDefaultValue = false)]
        public string PaymentPolicy { get; set; }

        /// <summary>
        /// 个人收款码转账是否支持因公付。可选值：0（不支持）、1（支持）
        /// </summary>
        /// <value>个人收款码转账是否支持因公付。可选值：0（不支持）、1（支持）</value>
        [DataMember(Name = "personal_qrcode_mode", EmitDefaultValue = false)]
        public int PersonalQrcodeMode { get; set; }

        /// <summary>
        /// 使用规则描述
        /// </summary>
        /// <value>使用规则描述</value>
        [DataMember(Name = "standard_desc", EmitDefaultValue = false)]
        public string StandardDesc { get; set; }

        /// <summary>
        /// 修改的使用规则id
        /// </summary>
        /// <value>修改的使用规则id</value>
        [DataMember(Name = "standard_id", EmitDefaultValue = false)]
        public string StandardId { get; set; }

        /// <summary>
        /// 使用规则名称
        /// </summary>
        /// <value>使用规则名称</value>
        [DataMember(Name = "standard_name", EmitDefaultValue = false)]
        public string StandardName { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ModifyStandardInfo {\n");
            sb.Append("  AddConditionList: ").Append(AddConditionList).Append("\n");
            sb.Append("  ConsumeMode: ").Append(ConsumeMode).Append("\n");
            sb.Append("  DeleteConditionIdList: ").Append(DeleteConditionIdList).Append("\n");
            sb.Append("  ModifyConditionList: ").Append(ModifyConditionList).Append("\n");
            sb.Append("  OpenRuleId: ").Append(OpenRuleId).Append("\n");
            sb.Append("  PaymentPolicy: ").Append(PaymentPolicy).Append("\n");
            sb.Append("  PersonalQrcodeMode: ").Append(PersonalQrcodeMode).Append("\n");
            sb.Append("  StandardDesc: ").Append(StandardDesc).Append("\n");
            sb.Append("  StandardId: ").Append(StandardId).Append("\n");
            sb.Append("  StandardName: ").Append(StandardName).Append("\n");
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
            return this.Equals(input as ModifyStandardInfo);
        }

        /// <summary>
        /// Returns true if ModifyStandardInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of ModifyStandardInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ModifyStandardInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AddConditionList == input.AddConditionList ||
                    this.AddConditionList != null &&
                    input.AddConditionList != null &&
                    this.AddConditionList.SequenceEqual(input.AddConditionList)
                ) && 
                (
                    this.ConsumeMode == input.ConsumeMode ||
                    (this.ConsumeMode != null &&
                    this.ConsumeMode.Equals(input.ConsumeMode))
                ) && 
                (
                    this.DeleteConditionIdList == input.DeleteConditionIdList ||
                    this.DeleteConditionIdList != null &&
                    input.DeleteConditionIdList != null &&
                    this.DeleteConditionIdList.SequenceEqual(input.DeleteConditionIdList)
                ) && 
                (
                    this.ModifyConditionList == input.ModifyConditionList ||
                    this.ModifyConditionList != null &&
                    input.ModifyConditionList != null &&
                    this.ModifyConditionList.SequenceEqual(input.ModifyConditionList)
                ) && 
                (
                    this.OpenRuleId == input.OpenRuleId ||
                    (this.OpenRuleId != null &&
                    this.OpenRuleId.Equals(input.OpenRuleId))
                ) && 
                (
                    this.PaymentPolicy == input.PaymentPolicy ||
                    (this.PaymentPolicy != null &&
                    this.PaymentPolicy.Equals(input.PaymentPolicy))
                ) && 
                (
                    this.PersonalQrcodeMode == input.PersonalQrcodeMode ||
                    this.PersonalQrcodeMode.Equals(input.PersonalQrcodeMode)
                ) && 
                (
                    this.StandardDesc == input.StandardDesc ||
                    (this.StandardDesc != null &&
                    this.StandardDesc.Equals(input.StandardDesc))
                ) && 
                (
                    this.StandardId == input.StandardId ||
                    (this.StandardId != null &&
                    this.StandardId.Equals(input.StandardId))
                ) && 
                (
                    this.StandardName == input.StandardName ||
                    (this.StandardName != null &&
                    this.StandardName.Equals(input.StandardName))
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
                if (this.AddConditionList != null)
                {
                    hashCode = (hashCode * 59) + this.AddConditionList.GetHashCode();
                }
                if (this.ConsumeMode != null)
                {
                    hashCode = (hashCode * 59) + this.ConsumeMode.GetHashCode();
                }
                if (this.DeleteConditionIdList != null)
                {
                    hashCode = (hashCode * 59) + this.DeleteConditionIdList.GetHashCode();
                }
                if (this.ModifyConditionList != null)
                {
                    hashCode = (hashCode * 59) + this.ModifyConditionList.GetHashCode();
                }
                if (this.OpenRuleId != null)
                {
                    hashCode = (hashCode * 59) + this.OpenRuleId.GetHashCode();
                }
                if (this.PaymentPolicy != null)
                {
                    hashCode = (hashCode * 59) + this.PaymentPolicy.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.PersonalQrcodeMode.GetHashCode();
                if (this.StandardDesc != null)
                {
                    hashCode = (hashCode * 59) + this.StandardDesc.GetHashCode();
                }
                if (this.StandardId != null)
                {
                    hashCode = (hashCode * 59) + this.StandardId.GetHashCode();
                }
                if (this.StandardName != null)
                {
                    hashCode = (hashCode * 59) + this.StandardName.GetHashCode();
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
