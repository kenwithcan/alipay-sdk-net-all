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
    /// GavintestNewonline
    /// </summary>
    [DataContract(Name = "GavintestNewonline")]
    public partial class GavintestNewonline : IEquatable<GavintestNewonline>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="GavintestNewonline" /> class.
        /// </summary>
        /// <param name="dem">1.</param>
        /// <param name="_string">_string.</param>
        public GavintestNewonline(List<string> dem = default(List<string>), GavintestNewLeveaOne _string = default(GavintestNewLeveaOne))
        {
            this.Dem = dem;
            this.String = _string;
        }

        /// <summary>
        /// 1
        /// </summary>
        /// <value>1</value>
        [DataMember(Name = "dem", EmitDefaultValue = false)]
        public List<string> Dem { get; set; }

        /// <summary>
        /// Gets or Sets String
        /// </summary>
        [DataMember(Name = "string", EmitDefaultValue = false)]
        public GavintestNewLeveaOne String { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class GavintestNewonline {\n");
            sb.Append("  Dem: ").Append(Dem).Append("\n");
            sb.Append("  String: ").Append(String).Append("\n");
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
            return this.Equals(input as GavintestNewonline);
        }

        /// <summary>
        /// Returns true if GavintestNewonline instances are equal
        /// </summary>
        /// <param name="input">Instance of GavintestNewonline to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(GavintestNewonline input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Dem == input.Dem ||
                    this.Dem != null &&
                    input.Dem != null &&
                    this.Dem.SequenceEqual(input.Dem)
                ) && 
                (
                    this.String == input.String ||
                    (this.String != null &&
                    this.String.Equals(input.String))
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
                if (this.Dem != null)
                {
                    hashCode = (hashCode * 59) + this.Dem.GetHashCode();
                }
                if (this.String != null)
                {
                    hashCode = (hashCode * 59) + this.String.GetHashCode();
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
