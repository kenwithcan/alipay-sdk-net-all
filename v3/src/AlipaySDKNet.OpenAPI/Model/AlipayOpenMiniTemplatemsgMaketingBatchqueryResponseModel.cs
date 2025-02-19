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
    /// AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel")]
    public partial class AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel : IEquatable<AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel" /> class.
        /// </summary>
        /// <param name="marketingDeliveryDetailList">投放详情列表.</param>
        /// <param name="total">投放详情总条数.</param>
        public AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel(List<MarketingDeliveryDetail> marketingDeliveryDetailList = default(List<MarketingDeliveryDetail>), int total = default(int))
        {
            this.MarketingDeliveryDetailList = marketingDeliveryDetailList;
            this.Total = total;
        }

        /// <summary>
        /// 投放详情列表
        /// </summary>
        /// <value>投放详情列表</value>
        [DataMember(Name = "marketing_delivery_detail_list", EmitDefaultValue = false)]
        public List<MarketingDeliveryDetail> MarketingDeliveryDetailList { get; set; }

        /// <summary>
        /// 投放详情总条数
        /// </summary>
        /// <value>投放详情总条数</value>
        [DataMember(Name = "total", EmitDefaultValue = false)]
        public int Total { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel {\n");
            sb.Append("  MarketingDeliveryDetailList: ").Append(MarketingDeliveryDetailList).Append("\n");
            sb.Append("  Total: ").Append(Total).Append("\n");
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
            return this.Equals(input as AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenMiniTemplatemsgMaketingBatchqueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.MarketingDeliveryDetailList == input.MarketingDeliveryDetailList ||
                    this.MarketingDeliveryDetailList != null &&
                    input.MarketingDeliveryDetailList != null &&
                    this.MarketingDeliveryDetailList.SequenceEqual(input.MarketingDeliveryDetailList)
                ) && 
                (
                    this.Total == input.Total ||
                    this.Total.Equals(input.Total)
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
                if (this.MarketingDeliveryDetailList != null)
                {
                    hashCode = (hashCode * 59) + this.MarketingDeliveryDetailList.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.Total.GetHashCode();
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
