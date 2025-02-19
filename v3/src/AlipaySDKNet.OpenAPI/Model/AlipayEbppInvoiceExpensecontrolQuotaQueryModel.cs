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
    /// AlipayEbppInvoiceExpensecontrolQuotaQueryModel
    /// </summary>
    [DataContract(Name = "AlipayEbppInvoiceExpensecontrolQuotaQueryModel")]
    public partial class AlipayEbppInvoiceExpensecontrolQuotaQueryModel : IEquatable<AlipayEbppInvoiceExpensecontrolQuotaQueryModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceExpensecontrolQuotaQueryModel" /> class.
        /// </summary>
        /// <param name="accountId">企业共同账户ID.</param>
        /// <param name="agreementNo">授权签约协议号.</param>
        /// <param name="enterpriseId">企业id.</param>
        /// <param name="ownerId">额度所属者ID.</param>
        /// <param name="ownerOpenId">额度所属者开放ID.</param>
        /// <param name="ownerType">额度所属者类型.</param>
        /// <param name="pageNum">页码.</param>
        /// <param name="pageSize">每页条数.</param>
        /// <param name="quotaIdList">额度ID列表.</param>
        /// <param name="quotaType">额度类型.</param>
        /// <param name="targetId">额度维度ID.</param>
        /// <param name="targetType">额度维度.</param>
        public AlipayEbppInvoiceExpensecontrolQuotaQueryModel(string accountId = default(string), string agreementNo = default(string), string enterpriseId = default(string), string ownerId = default(string), string ownerOpenId = default(string), string ownerType = default(string), int pageNum = default(int), int pageSize = default(int), List<string> quotaIdList = default(List<string>), string quotaType = default(string), string targetId = default(string), string targetType = default(string))
        {
            this.AccountId = accountId;
            this.AgreementNo = agreementNo;
            this.EnterpriseId = enterpriseId;
            this.OwnerId = ownerId;
            this.OwnerOpenId = ownerOpenId;
            this.OwnerType = ownerType;
            this.PageNum = pageNum;
            this.PageSize = pageSize;
            this.QuotaIdList = quotaIdList;
            this.QuotaType = quotaType;
            this.TargetId = targetId;
            this.TargetType = targetType;
        }

        /// <summary>
        /// 企业共同账户ID
        /// </summary>
        /// <value>企业共同账户ID</value>
        [DataMember(Name = "account_id", EmitDefaultValue = false)]
        public string AccountId { get; set; }

        /// <summary>
        /// 授权签约协议号
        /// </summary>
        /// <value>授权签约协议号</value>
        [DataMember(Name = "agreement_no", EmitDefaultValue = false)]
        public string AgreementNo { get; set; }

        /// <summary>
        /// 企业id
        /// </summary>
        /// <value>企业id</value>
        [DataMember(Name = "enterprise_id", EmitDefaultValue = false)]
        public string EnterpriseId { get; set; }

        /// <summary>
        /// 额度所属者ID
        /// </summary>
        /// <value>额度所属者ID</value>
        [DataMember(Name = "owner_id", EmitDefaultValue = false)]
        public string OwnerId { get; set; }

        /// <summary>
        /// 额度所属者开放ID
        /// </summary>
        /// <value>额度所属者开放ID</value>
        [DataMember(Name = "owner_open_id", EmitDefaultValue = false)]
        public string OwnerOpenId { get; set; }

        /// <summary>
        /// 额度所属者类型
        /// </summary>
        /// <value>额度所属者类型</value>
        [DataMember(Name = "owner_type", EmitDefaultValue = false)]
        public string OwnerType { get; set; }

        /// <summary>
        /// 页码
        /// </summary>
        /// <value>页码</value>
        [DataMember(Name = "page_num", EmitDefaultValue = false)]
        public int PageNum { get; set; }

        /// <summary>
        /// 每页条数
        /// </summary>
        /// <value>每页条数</value>
        [DataMember(Name = "page_size", EmitDefaultValue = false)]
        public int PageSize { get; set; }

        /// <summary>
        /// 额度ID列表
        /// </summary>
        /// <value>额度ID列表</value>
        [DataMember(Name = "quota_id_list", EmitDefaultValue = false)]
        public List<string> QuotaIdList { get; set; }

        /// <summary>
        /// 额度类型
        /// </summary>
        /// <value>额度类型</value>
        [DataMember(Name = "quota_type", EmitDefaultValue = false)]
        public string QuotaType { get; set; }

        /// <summary>
        /// 额度维度ID
        /// </summary>
        /// <value>额度维度ID</value>
        [DataMember(Name = "target_id", EmitDefaultValue = false)]
        public string TargetId { get; set; }

        /// <summary>
        /// 额度维度
        /// </summary>
        /// <value>额度维度</value>
        [DataMember(Name = "target_type", EmitDefaultValue = false)]
        public string TargetType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEbppInvoiceExpensecontrolQuotaQueryModel {\n");
            sb.Append("  AccountId: ").Append(AccountId).Append("\n");
            sb.Append("  AgreementNo: ").Append(AgreementNo).Append("\n");
            sb.Append("  EnterpriseId: ").Append(EnterpriseId).Append("\n");
            sb.Append("  OwnerId: ").Append(OwnerId).Append("\n");
            sb.Append("  OwnerOpenId: ").Append(OwnerOpenId).Append("\n");
            sb.Append("  OwnerType: ").Append(OwnerType).Append("\n");
            sb.Append("  PageNum: ").Append(PageNum).Append("\n");
            sb.Append("  PageSize: ").Append(PageSize).Append("\n");
            sb.Append("  QuotaIdList: ").Append(QuotaIdList).Append("\n");
            sb.Append("  QuotaType: ").Append(QuotaType).Append("\n");
            sb.Append("  TargetId: ").Append(TargetId).Append("\n");
            sb.Append("  TargetType: ").Append(TargetType).Append("\n");
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
            return this.Equals(input as AlipayEbppInvoiceExpensecontrolQuotaQueryModel);
        }

        /// <summary>
        /// Returns true if AlipayEbppInvoiceExpensecontrolQuotaQueryModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEbppInvoiceExpensecontrolQuotaQueryModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEbppInvoiceExpensecontrolQuotaQueryModel input)
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
                    this.AgreementNo == input.AgreementNo ||
                    (this.AgreementNo != null &&
                    this.AgreementNo.Equals(input.AgreementNo))
                ) && 
                (
                    this.EnterpriseId == input.EnterpriseId ||
                    (this.EnterpriseId != null &&
                    this.EnterpriseId.Equals(input.EnterpriseId))
                ) && 
                (
                    this.OwnerId == input.OwnerId ||
                    (this.OwnerId != null &&
                    this.OwnerId.Equals(input.OwnerId))
                ) && 
                (
                    this.OwnerOpenId == input.OwnerOpenId ||
                    (this.OwnerOpenId != null &&
                    this.OwnerOpenId.Equals(input.OwnerOpenId))
                ) && 
                (
                    this.OwnerType == input.OwnerType ||
                    (this.OwnerType != null &&
                    this.OwnerType.Equals(input.OwnerType))
                ) && 
                (
                    this.PageNum == input.PageNum ||
                    this.PageNum.Equals(input.PageNum)
                ) && 
                (
                    this.PageSize == input.PageSize ||
                    this.PageSize.Equals(input.PageSize)
                ) && 
                (
                    this.QuotaIdList == input.QuotaIdList ||
                    this.QuotaIdList != null &&
                    input.QuotaIdList != null &&
                    this.QuotaIdList.SequenceEqual(input.QuotaIdList)
                ) && 
                (
                    this.QuotaType == input.QuotaType ||
                    (this.QuotaType != null &&
                    this.QuotaType.Equals(input.QuotaType))
                ) && 
                (
                    this.TargetId == input.TargetId ||
                    (this.TargetId != null &&
                    this.TargetId.Equals(input.TargetId))
                ) && 
                (
                    this.TargetType == input.TargetType ||
                    (this.TargetType != null &&
                    this.TargetType.Equals(input.TargetType))
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
                if (this.AgreementNo != null)
                {
                    hashCode = (hashCode * 59) + this.AgreementNo.GetHashCode();
                }
                if (this.EnterpriseId != null)
                {
                    hashCode = (hashCode * 59) + this.EnterpriseId.GetHashCode();
                }
                if (this.OwnerId != null)
                {
                    hashCode = (hashCode * 59) + this.OwnerId.GetHashCode();
                }
                if (this.OwnerOpenId != null)
                {
                    hashCode = (hashCode * 59) + this.OwnerOpenId.GetHashCode();
                }
                if (this.OwnerType != null)
                {
                    hashCode = (hashCode * 59) + this.OwnerType.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.PageNum.GetHashCode();
                hashCode = (hashCode * 59) + this.PageSize.GetHashCode();
                if (this.QuotaIdList != null)
                {
                    hashCode = (hashCode * 59) + this.QuotaIdList.GetHashCode();
                }
                if (this.QuotaType != null)
                {
                    hashCode = (hashCode * 59) + this.QuotaType.GetHashCode();
                }
                if (this.TargetId != null)
                {
                    hashCode = (hashCode * 59) + this.TargetId.GetHashCode();
                }
                if (this.TargetType != null)
                {
                    hashCode = (hashCode * 59) + this.TargetType.GetHashCode();
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
