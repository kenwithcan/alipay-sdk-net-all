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
    /// AlipayEbppInvoiceExpenserulesProjectrulesModifyModel
    /// </summary>
    [DataContract(Name = "AlipayEbppInvoiceExpenserulesProjectrulesModifyModel")]
    public partial class AlipayEbppInvoiceExpenserulesProjectrulesModifyModel : IEquatable<AlipayEbppInvoiceExpenserulesProjectrulesModifyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceExpenserulesProjectrulesModifyModel" /> class.
        /// </summary>
        /// <param name="accountId">企业ID.</param>
        /// <param name="action">修改操作 枚举值：MODIFY_RULE（修改费控条件），仅支持MODIFY_RULE.</param>
        /// <param name="agreementNo">授权签约协议号.</param>
        /// <param name="expenseCtrlRuleInfoGroupList">费控规则列表.</param>
        /// <param name="projectId">项目ID.</param>
        public AlipayEbppInvoiceExpenserulesProjectrulesModifyModel(string accountId = default(string), string action = default(string), string agreementNo = default(string), List<ExpenseCtrRuleGroupInfo> expenseCtrlRuleInfoGroupList = default(List<ExpenseCtrRuleGroupInfo>), string projectId = default(string))
        {
            this.AccountId = accountId;
            this.Action = action;
            this.AgreementNo = agreementNo;
            this.ExpenseCtrlRuleInfoGroupList = expenseCtrlRuleInfoGroupList;
            this.ProjectId = projectId;
        }

        /// <summary>
        /// 企业ID
        /// </summary>
        /// <value>企业ID</value>
        [DataMember(Name = "account_id", EmitDefaultValue = false)]
        public string AccountId { get; set; }

        /// <summary>
        /// 修改操作 枚举值：MODIFY_RULE（修改费控条件），仅支持MODIFY_RULE
        /// </summary>
        /// <value>修改操作 枚举值：MODIFY_RULE（修改费控条件），仅支持MODIFY_RULE</value>
        [DataMember(Name = "action", EmitDefaultValue = false)]
        public string Action { get; set; }

        /// <summary>
        /// 授权签约协议号
        /// </summary>
        /// <value>授权签约协议号</value>
        [DataMember(Name = "agreement_no", EmitDefaultValue = false)]
        public string AgreementNo { get; set; }

        /// <summary>
        /// 费控规则列表
        /// </summary>
        /// <value>费控规则列表</value>
        [DataMember(Name = "expense_ctrl_rule_info_group_list", EmitDefaultValue = false)]
        public List<ExpenseCtrRuleGroupInfo> ExpenseCtrlRuleInfoGroupList { get; set; }

        /// <summary>
        /// 项目ID
        /// </summary>
        /// <value>项目ID</value>
        [DataMember(Name = "project_id", EmitDefaultValue = false)]
        public string ProjectId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEbppInvoiceExpenserulesProjectrulesModifyModel {\n");
            sb.Append("  AccountId: ").Append(AccountId).Append("\n");
            sb.Append("  Action: ").Append(Action).Append("\n");
            sb.Append("  AgreementNo: ").Append(AgreementNo).Append("\n");
            sb.Append("  ExpenseCtrlRuleInfoGroupList: ").Append(ExpenseCtrlRuleInfoGroupList).Append("\n");
            sb.Append("  ProjectId: ").Append(ProjectId).Append("\n");
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
            return this.Equals(input as AlipayEbppInvoiceExpenserulesProjectrulesModifyModel);
        }

        /// <summary>
        /// Returns true if AlipayEbppInvoiceExpenserulesProjectrulesModifyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEbppInvoiceExpenserulesProjectrulesModifyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEbppInvoiceExpenserulesProjectrulesModifyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AccountId == input.AccountId ||
                    (this.AccountId != null &&
                    this.AccountId.Equals(input.AccountId))
                ) && 
                (
                    this.Action == input.Action ||
                    (this.Action != null &&
                    this.Action.Equals(input.Action))
                ) && 
                (
                    this.AgreementNo == input.AgreementNo ||
                    (this.AgreementNo != null &&
                    this.AgreementNo.Equals(input.AgreementNo))
                ) && 
                (
                    this.ExpenseCtrlRuleInfoGroupList == input.ExpenseCtrlRuleInfoGroupList ||
                    this.ExpenseCtrlRuleInfoGroupList != null &&
                    input.ExpenseCtrlRuleInfoGroupList != null &&
                    this.ExpenseCtrlRuleInfoGroupList.SequenceEqual(input.ExpenseCtrlRuleInfoGroupList)
                ) && 
                (
                    this.ProjectId == input.ProjectId ||
                    (this.ProjectId != null &&
                    this.ProjectId.Equals(input.ProjectId))
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
                if (this.AccountId != null)
                {
                    hashCode = (hashCode * 59) + this.AccountId.GetHashCode();
                }
                if (this.Action != null)
                {
                    hashCode = (hashCode * 59) + this.Action.GetHashCode();
                }
                if (this.AgreementNo != null)
                {
                    hashCode = (hashCode * 59) + this.AgreementNo.GetHashCode();
                }
                if (this.ExpenseCtrlRuleInfoGroupList != null)
                {
                    hashCode = (hashCode * 59) + this.ExpenseCtrlRuleInfoGroupList.GetHashCode();
                }
                if (this.ProjectId != null)
                {
                    hashCode = (hashCode * 59) + this.ProjectId.GetHashCode();
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
