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
    /// FillContent
    /// </summary>
    [DataContract(Name = "FillContent")]
    public partial class FillContent : IEquatable<FillContent>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FillContent" /> class.
        /// </summary>
        /// <param name="structKey">模板组件自定义key.</param>
        /// <param name="value">模板值,该值长度取决于配置模板时该字段的限制.</param>
        public FillContent(string structKey = default(string), string value = default(string))
        {
            this.StructKey = structKey;
            this.Value = value;
        }

        /// <summary>
        /// 模板组件自定义key
        /// </summary>
        /// <value>模板组件自定义key</value>
        [DataMember(Name = "struct_key", EmitDefaultValue = false)]
        public string StructKey { get; set; }

        /// <summary>
        /// 模板值,该值长度取决于配置模板时该字段的限制
        /// </summary>
        /// <value>模板值,该值长度取决于配置模板时该字段的限制</value>
        [DataMember(Name = "value", EmitDefaultValue = false)]
        public string Value { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class FillContent {\n");
            sb.Append("  StructKey: ").Append(StructKey).Append("\n");
            sb.Append("  Value: ").Append(Value).Append("\n");
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
            return this.Equals(input as FillContent);
        }

        /// <summary>
        /// Returns true if FillContent instances are equal
        /// </summary>
        /// <param name="input">Instance of FillContent to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(FillContent input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.StructKey == input.StructKey ||
                    (this.StructKey != null &&
                    this.StructKey.Equals(input.StructKey))
                ) && 
                (
                    this.Value == input.Value ||
                    (this.Value != null &&
                    this.Value.Equals(input.Value))
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
                if (this.StructKey != null)
                {
                    hashCode = (hashCode * 59) + this.StructKey.GetHashCode();
                }
                if (this.Value != null)
                {
                    hashCode = (hashCode * 59) + this.Value.GetHashCode();
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
