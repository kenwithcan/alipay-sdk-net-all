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
    /// VoucherPackageConsultResult
    /// </summary>
    [DataContract(Name = "VoucherPackageConsultResult")]
    public partial class VoucherPackageConsultResult : IEquatable<VoucherPackageConsultResult>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VoucherPackageConsultResult" /> class.
        /// </summary>
        /// <param name="consultResultCode">券包购买咨询结果code： SUCCESS：可以领取； PRODUCT_NOT_ENABLE：产品不可用； NOT_IN_SELL_TIME：不在销售时间内； PRODUCT_SOLD_OUT：产品售罄； USER_PURCHASE_LIMIT：用户购买上限； OTHER：不可购买，未知原因.</param>
        /// <param name="voucherPackageId">券包id.</param>
        public VoucherPackageConsultResult(string consultResultCode = default(string), string voucherPackageId = default(string))
        {
            this.ConsultResultCode = consultResultCode;
            this.VoucherPackageId = voucherPackageId;
        }

        /// <summary>
        /// 券包购买咨询结果code： SUCCESS：可以领取； PRODUCT_NOT_ENABLE：产品不可用； NOT_IN_SELL_TIME：不在销售时间内； PRODUCT_SOLD_OUT：产品售罄； USER_PURCHASE_LIMIT：用户购买上限； OTHER：不可购买，未知原因
        /// </summary>
        /// <value>券包购买咨询结果code： SUCCESS：可以领取； PRODUCT_NOT_ENABLE：产品不可用； NOT_IN_SELL_TIME：不在销售时间内； PRODUCT_SOLD_OUT：产品售罄； USER_PURCHASE_LIMIT：用户购买上限； OTHER：不可购买，未知原因</value>
        [DataMember(Name = "consult_result_code", EmitDefaultValue = false)]
        public string ConsultResultCode { get; set; }

        /// <summary>
        /// 券包id
        /// </summary>
        /// <value>券包id</value>
        [DataMember(Name = "voucher_package_id", EmitDefaultValue = false)]
        public string VoucherPackageId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class VoucherPackageConsultResult {\n");
            sb.Append("  ConsultResultCode: ").Append(ConsultResultCode).Append("\n");
            sb.Append("  VoucherPackageId: ").Append(VoucherPackageId).Append("\n");
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
            return this.Equals(input as VoucherPackageConsultResult);
        }

        /// <summary>
        /// Returns true if VoucherPackageConsultResult instances are equal
        /// </summary>
        /// <param name="input">Instance of VoucherPackageConsultResult to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VoucherPackageConsultResult input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ConsultResultCode == input.ConsultResultCode ||
                    (this.ConsultResultCode != null &&
                    this.ConsultResultCode.Equals(input.ConsultResultCode))
                ) && 
                (
                    this.VoucherPackageId == input.VoucherPackageId ||
                    (this.VoucherPackageId != null &&
                    this.VoucherPackageId.Equals(input.VoucherPackageId))
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
                if (this.ConsultResultCode != null)
                {
                    hashCode = (hashCode * 59) + this.ConsultResultCode.GetHashCode();
                }
                if (this.VoucherPackageId != null)
                {
                    hashCode = (hashCode * 59) + this.VoucherPackageId.GetHashCode();
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
