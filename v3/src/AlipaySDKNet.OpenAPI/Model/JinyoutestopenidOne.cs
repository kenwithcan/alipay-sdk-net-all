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
    /// JinyoutestopenidOne
    /// </summary>
    [DataContract(Name = "JinyoutestopenidOne")]
    public partial class JinyoutestopenidOne : IEquatable<JinyoutestopenidOne>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="JinyoutestopenidOne" /> class.
        /// </summary>
        /// <param name="c1">我晚点.</param>
        /// <param name="q">1.</param>
        /// <param name="q1OpenId">1.</param>
        public JinyoutestopenidOne(string c1 = default(string), string q = default(string), string q1OpenId = default(string))
        {
            this.C1 = c1;
            this.Q = q;
            this.Q1OpenId = q1OpenId;
        }

        /// <summary>
        /// 我晚点
        /// </summary>
        /// <value>我晚点</value>
        [DataMember(Name = "c_1", EmitDefaultValue = false)]
        public string C1 { get; set; }

        /// <summary>
        /// 1
        /// </summary>
        /// <value>1</value>
        [DataMember(Name = "q", EmitDefaultValue = false)]
        public string Q { get; set; }

        /// <summary>
        /// 1
        /// </summary>
        /// <value>1</value>
        [DataMember(Name = "q_1_open_id", EmitDefaultValue = false)]
        public string Q1OpenId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class JinyoutestopenidOne {\n");
            sb.Append("  C1: ").Append(C1).Append("\n");
            sb.Append("  Q: ").Append(Q).Append("\n");
            sb.Append("  Q1OpenId: ").Append(Q1OpenId).Append("\n");
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
            return this.Equals(input as JinyoutestopenidOne);
        }

        /// <summary>
        /// Returns true if JinyoutestopenidOne instances are equal
        /// </summary>
        /// <param name="input">Instance of JinyoutestopenidOne to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(JinyoutestopenidOne input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.C1 == input.C1 ||
                    (this.C1 != null &&
                    this.C1.Equals(input.C1))
                ) && 
                (
                    this.Q == input.Q ||
                    (this.Q != null &&
                    this.Q.Equals(input.Q))
                ) && 
                (
                    this.Q1OpenId == input.Q1OpenId ||
                    (this.Q1OpenId != null &&
                    this.Q1OpenId.Equals(input.Q1OpenId))
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
                if (this.C1 != null)
                {
                    hashCode = (hashCode * 59) + this.C1.GetHashCode();
                }
                if (this.Q != null)
                {
                    hashCode = (hashCode * 59) + this.Q.GetHashCode();
                }
                if (this.Q1OpenId != null)
                {
                    hashCode = (hashCode * 59) + this.Q1OpenId.GetHashCode();
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
