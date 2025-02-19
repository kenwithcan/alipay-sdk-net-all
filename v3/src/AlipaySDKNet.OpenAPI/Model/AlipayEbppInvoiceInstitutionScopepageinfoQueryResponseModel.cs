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
    /// AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel")]
    public partial class AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel : IEquatable<AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel" /> class.
        /// </summary>
        /// <param name="adapterType">制度适用范围类型.</param>
        /// <param name="onwerOpenIdList">适配开放id列表.</param>
        /// <param name="ownerIdList">适配id列表.</param>
        /// <param name="pageNum">页码.</param>
        /// <param name="pageSize">页大小.</param>
        /// <param name="totalPageCount">总页数.</param>
        public AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel(string adapterType = default(string), List<string> onwerOpenIdList = default(List<string>), List<string> ownerIdList = default(List<string>), int pageNum = default(int), int pageSize = default(int), int totalPageCount = default(int))
        {
            this.AdapterType = adapterType;
            this.OnwerOpenIdList = onwerOpenIdList;
            this.OwnerIdList = ownerIdList;
            this.PageNum = pageNum;
            this.PageSize = pageSize;
            this.TotalPageCount = totalPageCount;
        }

        /// <summary>
        /// 制度适用范围类型
        /// </summary>
        /// <value>制度适用范围类型</value>
        [DataMember(Name = "adapter_type", EmitDefaultValue = false)]
        public string AdapterType { get; set; }

        /// <summary>
        /// 适配开放id列表
        /// </summary>
        /// <value>适配开放id列表</value>
        [DataMember(Name = "onwer_open_id_list", EmitDefaultValue = false)]
        public List<string> OnwerOpenIdList { get; set; }

        /// <summary>
        /// 适配id列表
        /// </summary>
        /// <value>适配id列表</value>
        [DataMember(Name = "owner_id_list", EmitDefaultValue = false)]
        public List<string> OwnerIdList { get; set; }

        /// <summary>
        /// 页码
        /// </summary>
        /// <value>页码</value>
        [DataMember(Name = "page_num", EmitDefaultValue = false)]
        public int PageNum { get; set; }

        /// <summary>
        /// 页大小
        /// </summary>
        /// <value>页大小</value>
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
            sb.Append("class AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel {\n");
            sb.Append("  AdapterType: ").Append(AdapterType).Append("\n");
            sb.Append("  OnwerOpenIdList: ").Append(OnwerOpenIdList).Append("\n");
            sb.Append("  OwnerIdList: ").Append(OwnerIdList).Append("\n");
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
            return this.Equals(input as AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEbppInvoiceInstitutionScopepageinfoQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AdapterType == input.AdapterType ||
                    (this.AdapterType != null &&
                    this.AdapterType.Equals(input.AdapterType))
                ) && 
                (
                    this.OnwerOpenIdList == input.OnwerOpenIdList ||
                    this.OnwerOpenIdList != null &&
                    input.OnwerOpenIdList != null &&
                    this.OnwerOpenIdList.SequenceEqual(input.OnwerOpenIdList)
                ) && 
                (
                    this.OwnerIdList == input.OwnerIdList ||
                    this.OwnerIdList != null &&
                    input.OwnerIdList != null &&
                    this.OwnerIdList.SequenceEqual(input.OwnerIdList)
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
                if (this.AdapterType != null)
                {
                    hashCode = (hashCode * 59) + this.AdapterType.GetHashCode();
                }
                if (this.OnwerOpenIdList != null)
                {
                    hashCode = (hashCode * 59) + this.OnwerOpenIdList.GetHashCode();
                }
                if (this.OwnerIdList != null)
                {
                    hashCode = (hashCode * 59) + this.OwnerIdList.GetHashCode();
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
