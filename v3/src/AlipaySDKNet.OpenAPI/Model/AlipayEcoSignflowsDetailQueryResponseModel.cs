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
    /// AlipayEcoSignflowsDetailQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayEcoSignflowsDetailQueryResponseModel")]
    public partial class AlipayEcoSignflowsDetailQueryResponseModel : IEquatable<AlipayEcoSignflowsDetailQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEcoSignflowsDetailQueryResponseModel" /> class.
        /// </summary>
        /// <param name="attachments">attachments.</param>
        /// <param name="docs">docs.</param>
        public AlipayEcoSignflowsDetailQueryResponseModel(AttachmentDetail attachments = default(AttachmentDetail), DocInfo docs = default(DocInfo))
        {
            this.Attachments = attachments;
            this.Docs = docs;
        }

        /// <summary>
        /// Gets or Sets Attachments
        /// </summary>
        [DataMember(Name = "attachments", EmitDefaultValue = false)]
        public AttachmentDetail Attachments { get; set; }

        /// <summary>
        /// Gets or Sets Docs
        /// </summary>
        [DataMember(Name = "docs", EmitDefaultValue = false)]
        public DocInfo Docs { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEcoSignflowsDetailQueryResponseModel {\n");
            sb.Append("  Attachments: ").Append(Attachments).Append("\n");
            sb.Append("  Docs: ").Append(Docs).Append("\n");
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
            return this.Equals(input as AlipayEcoSignflowsDetailQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayEcoSignflowsDetailQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEcoSignflowsDetailQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEcoSignflowsDetailQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Attachments == input.Attachments ||
                    (this.Attachments != null &&
                    this.Attachments.Equals(input.Attachments))
                ) && 
                (
                    this.Docs == input.Docs ||
                    (this.Docs != null &&
                    this.Docs.Equals(input.Docs))
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
                if (this.Attachments != null)
                {
                    hashCode = (hashCode * 59) + this.Attachments.GetHashCode();
                }
                if (this.Docs != null)
                {
                    hashCode = (hashCode * 59) + this.Docs.GetHashCode();
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
