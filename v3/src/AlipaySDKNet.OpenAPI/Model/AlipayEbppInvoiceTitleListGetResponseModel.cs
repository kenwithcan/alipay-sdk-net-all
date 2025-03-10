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
    /// AlipayEbppInvoiceTitleListGetResponseModel
    /// </summary>
    [DataContract(Name = "AlipayEbppInvoiceTitleListGetResponseModel")]
    public partial class AlipayEbppInvoiceTitleListGetResponseModel : IEquatable<AlipayEbppInvoiceTitleListGetResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEbppInvoiceTitleListGetResponseModel" /> class.
        /// </summary>
        /// <param name="titleList">抬头列表.</param>
        public AlipayEbppInvoiceTitleListGetResponseModel(List<InvoiceTitleModel> titleList = default(List<InvoiceTitleModel>))
        {
            this.TitleList = titleList;
        }

        /// <summary>
        /// 抬头列表
        /// </summary>
        /// <value>抬头列表</value>
        [DataMember(Name = "title_list", EmitDefaultValue = false)]
        public List<InvoiceTitleModel> TitleList { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEbppInvoiceTitleListGetResponseModel {\n");
            sb.Append("  TitleList: ").Append(TitleList).Append("\n");
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
            return this.Equals(input as AlipayEbppInvoiceTitleListGetResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayEbppInvoiceTitleListGetResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEbppInvoiceTitleListGetResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEbppInvoiceTitleListGetResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.TitleList == input.TitleList ||
                    this.TitleList != null &&
                    input.TitleList != null &&
                    this.TitleList.SequenceEqual(input.TitleList)
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
                if (this.TitleList != null)
                {
                    hashCode = (hashCode * 59) + this.TitleList.GetHashCode();
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
