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
    /// AlipayMarketingActivityVoucherpackageBatchqueryModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingActivityVoucherpackageBatchqueryModel")]
    public partial class AlipayMarketingActivityVoucherpackageBatchqueryModel : IEquatable<AlipayMarketingActivityVoucherpackageBatchqueryModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingActivityVoucherpackageBatchqueryModel" /> class.
        /// </summary>
        /// <param name="pageNum">分页参数，需要查询的页码，起始页是1.</param>
        /// <param name="pageSize">分页参数，每页记录数，最大不可超过30.</param>
        /// <param name="voucherPackagePurchaseStartTime">券包购买开始时间。 格式为：yyyy-MM-dd HH:mm:ss.</param>
        /// <param name="voucherPackageStatus">券包状态.</param>
        public AlipayMarketingActivityVoucherpackageBatchqueryModel(int pageNum = default(int), int pageSize = default(int), string voucherPackagePurchaseStartTime = default(string), string voucherPackageStatus = default(string))
        {
            this.PageNum = pageNum;
            this.PageSize = pageSize;
            this.VoucherPackagePurchaseStartTime = voucherPackagePurchaseStartTime;
            this.VoucherPackageStatus = voucherPackageStatus;
        }

        /// <summary>
        /// 分页参数，需要查询的页码，起始页是1
        /// </summary>
        /// <value>分页参数，需要查询的页码，起始页是1</value>
        [DataMember(Name = "page_num", EmitDefaultValue = false)]
        public int PageNum { get; set; }

        /// <summary>
        /// 分页参数，每页记录数，最大不可超过30
        /// </summary>
        /// <value>分页参数，每页记录数，最大不可超过30</value>
        [DataMember(Name = "page_size", EmitDefaultValue = false)]
        public int PageSize { get; set; }

        /// <summary>
        /// 券包购买开始时间。 格式为：yyyy-MM-dd HH:mm:ss
        /// </summary>
        /// <value>券包购买开始时间。 格式为：yyyy-MM-dd HH:mm:ss</value>
        [DataMember(Name = "voucher_package_purchase_start_time", EmitDefaultValue = false)]
        public string VoucherPackagePurchaseStartTime { get; set; }

        /// <summary>
        /// 券包状态
        /// </summary>
        /// <value>券包状态</value>
        [DataMember(Name = "voucher_package_status", EmitDefaultValue = false)]
        public string VoucherPackageStatus { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMarketingActivityVoucherpackageBatchqueryModel {\n");
            sb.Append("  PageNum: ").Append(PageNum).Append("\n");
            sb.Append("  PageSize: ").Append(PageSize).Append("\n");
            sb.Append("  VoucherPackagePurchaseStartTime: ").Append(VoucherPackagePurchaseStartTime).Append("\n");
            sb.Append("  VoucherPackageStatus: ").Append(VoucherPackageStatus).Append("\n");
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
            return this.Equals(input as AlipayMarketingActivityVoucherpackageBatchqueryModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingActivityVoucherpackageBatchqueryModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingActivityVoucherpackageBatchqueryModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingActivityVoucherpackageBatchqueryModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.PageNum == input.PageNum ||
                    this.PageNum.Equals(input.PageNum)
                ) && 
                (
                    this.PageSize == input.PageSize ||
                    this.PageSize.Equals(input.PageSize)
                ) && 
                (
                    this.VoucherPackagePurchaseStartTime == input.VoucherPackagePurchaseStartTime ||
                    (this.VoucherPackagePurchaseStartTime != null &&
                    this.VoucherPackagePurchaseStartTime.Equals(input.VoucherPackagePurchaseStartTime))
                ) && 
                (
                    this.VoucherPackageStatus == input.VoucherPackageStatus ||
                    (this.VoucherPackageStatus != null &&
                    this.VoucherPackageStatus.Equals(input.VoucherPackageStatus))
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
                hashCode = (hashCode * 59) + this.PageNum.GetHashCode();
                hashCode = (hashCode * 59) + this.PageSize.GetHashCode();
                if (this.VoucherPackagePurchaseStartTime != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherPackagePurchaseStartTime.GetHashCode();
                }
                if (this.VoucherPackageStatus != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherPackageStatus.GetHashCode();
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
