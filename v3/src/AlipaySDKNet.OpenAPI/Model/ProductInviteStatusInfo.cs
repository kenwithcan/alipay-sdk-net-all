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
    /// ProductInviteStatusInfo
    /// </summary>
    [DataContract(Name = "ProductInviteStatusInfo")]
    public partial class ProductInviteStatusInfo : IEquatable<ProductInviteStatusInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ProductInviteStatusInfo" /> class.
        /// </summary>
        /// <param name="productCode">产品编码.</param>
        /// <param name="productName">产品名称.</param>
        /// <param name="status">NONE：未签约，表示还没有签约该产品 MERCHANT_AUDITING：审核中，已经有合约在审核中，请等待审核完成 MERCHANT_CONFIRM_SUCCESS：已生效，表示合约已经生效，不需要再签约了 MERCHANT_APPLY_ORDER_CANCELED：审核未通过.</param>
        public ProductInviteStatusInfo(string productCode = default(string), string productName = default(string), string status = default(string))
        {
            this.ProductCode = productCode;
            this.ProductName = productName;
            this.Status = status;
        }

        /// <summary>
        /// 产品编码
        /// </summary>
        /// <value>产品编码</value>
        [DataMember(Name = "product_code", EmitDefaultValue = false)]
        public string ProductCode { get; set; }

        /// <summary>
        /// 产品名称
        /// </summary>
        /// <value>产品名称</value>
        [DataMember(Name = "product_name", EmitDefaultValue = false)]
        public string ProductName { get; set; }

        /// <summary>
        /// NONE：未签约，表示还没有签约该产品 MERCHANT_AUDITING：审核中，已经有合约在审核中，请等待审核完成 MERCHANT_CONFIRM_SUCCESS：已生效，表示合约已经生效，不需要再签约了 MERCHANT_APPLY_ORDER_CANCELED：审核未通过
        /// </summary>
        /// <value>NONE：未签约，表示还没有签约该产品 MERCHANT_AUDITING：审核中，已经有合约在审核中，请等待审核完成 MERCHANT_CONFIRM_SUCCESS：已生效，表示合约已经生效，不需要再签约了 MERCHANT_APPLY_ORDER_CANCELED：审核未通过</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ProductInviteStatusInfo {\n");
            sb.Append("  ProductCode: ").Append(ProductCode).Append("\n");
            sb.Append("  ProductName: ").Append(ProductName).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
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
            return this.Equals(input as ProductInviteStatusInfo);
        }

        /// <summary>
        /// Returns true if ProductInviteStatusInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of ProductInviteStatusInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ProductInviteStatusInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ProductCode == input.ProductCode ||
                    (this.ProductCode != null &&
                    this.ProductCode.Equals(input.ProductCode))
                ) && 
                (
                    this.ProductName == input.ProductName ||
                    (this.ProductName != null &&
                    this.ProductName.Equals(input.ProductName))
                ) && 
                (
                    this.Status == input.Status ||
                    (this.Status != null &&
                    this.Status.Equals(input.Status))
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
                if (this.ProductCode != null)
                {
                    hashCode = (hashCode * 59) + this.ProductCode.GetHashCode();
                }
                if (this.ProductName != null)
                {
                    hashCode = (hashCode * 59) + this.ProductName.GetHashCode();
                }
                if (this.Status != null)
                {
                    hashCode = (hashCode * 59) + this.Status.GetHashCode();
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
