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
    /// AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel")]
    public partial class AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel : IEquatable<AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel" /> class.
        /// </summary>
        /// <param name="expenseQuotaInfoList">额度列表.</param>
        /// <param name="pageNum">当前页数.</param>
        /// <param name="pageSize">当前记录数.</param>
        /// <param name="totalPageCount">总页数.</param>
        public AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel(List<ExpenseQuotaInfo> expenseQuotaInfoList = default(List<ExpenseQuotaInfo>), int pageNum = default(int), int pageSize = default(int), int totalPageCount = default(int))
        {
            this.ExpenseQuotaInfoList = expenseQuotaInfoList;
            this.PageNum = pageNum;
            this.PageSize = pageSize;
            this.TotalPageCount = totalPageCount;
        }

        /// <summary>
        /// 额度列表
        /// </summary>
        /// <value>额度列表</value>
        [DataMember(Name = "expense_quota_info_list", EmitDefaultValue = false)]
        public List<ExpenseQuotaInfo> ExpenseQuotaInfoList { get; set; }

        /// <summary>
        /// 当前页数
        /// </summary>
        /// <value>当前页数</value>
        [DataMember(Name = "page_num", EmitDefaultValue = false)]
        public int PageNum { get; set; }

        /// <summary>
        /// 当前记录数
        /// </summary>
        /// <value>当前记录数</value>
        [DataMember(Name = "page_size", EmitDefaultValue = false)]
        public int PageSize { get; set; }

        /// <summary>
        /// 总页数
        /// </summary>
        /// <value>总页数</value>
        [DataMember(Name = "total_page_count", EmitDefaultValue = false)]
        public int TotalPageCount { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel {\n");
            sb.Append("  ExpenseQuotaInfoList: ").Append(ExpenseQuotaInfoList).Append("\n");
            sb.Append("  PageNum: ").Append(PageNum).Append("\n");
            sb.Append("  PageSize: ").Append(PageSize).Append("\n");
            sb.Append("  TotalPageCount: ").Append(TotalPageCount).Append("\n");
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
            return this.Equals(input as AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEbppInvoiceExpensecontrolQuotaQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ExpenseQuotaInfoList == input.ExpenseQuotaInfoList ||
                    this.ExpenseQuotaInfoList != null &&
                    input.ExpenseQuotaInfoList != null &&
                    this.ExpenseQuotaInfoList.SequenceEqual(input.ExpenseQuotaInfoList)
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
                    this.TotalPageCount == input.TotalPageCount ||
                    this.TotalPageCount.Equals(input.TotalPageCount)
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
                if (this.ExpenseQuotaInfoList != null)
                {
                    hashCode = (hashCode * 59) + this.ExpenseQuotaInfoList.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.PageNum.GetHashCode();
                hashCode = (hashCode * 59) + this.PageSize.GetHashCode();
                hashCode = (hashCode * 59) + this.TotalPageCount.GetHashCode();
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
