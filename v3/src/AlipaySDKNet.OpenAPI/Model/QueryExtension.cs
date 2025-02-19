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
    /// QueryExtension
    /// </summary>
    [DataContract(Name = "QueryExtension")]
    public partial class QueryExtension : IEquatable<QueryExtension>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="QueryExtension" /> class.
        /// </summary>
        /// <param name="areas">扩展区列表.</param>
        /// <param name="extensionKey">扩展区套id.</param>
        /// <param name="labelRules">标签规则列表.</param>
        /// <param name="status">扩展区状态，\&quot;ON\&quot;代表上线，\&quot;OFF\&quot;代表下线，只有上线的扩展区才能被用户看到.</param>
        public QueryExtension(List<ExtensionArea> areas = default(List<ExtensionArea>), string extensionKey = default(string), List<QueryLabelRule> labelRules = default(List<QueryLabelRule>), string status = default(string))
        {
            this.Areas = areas;
            this.ExtensionKey = extensionKey;
            this.LabelRules = labelRules;
            this.Status = status;
        }

        /// <summary>
        /// 扩展区列表
        /// </summary>
        /// <value>扩展区列表</value>
        [DataMember(Name = "areas", EmitDefaultValue = false)]
        public List<ExtensionArea> Areas { get; set; }

        /// <summary>
        /// 扩展区套id
        /// </summary>
        /// <value>扩展区套id</value>
        [DataMember(Name = "extension_key", EmitDefaultValue = false)]
        public string ExtensionKey { get; set; }

        /// <summary>
        /// 标签规则列表
        /// </summary>
        /// <value>标签规则列表</value>
        [DataMember(Name = "label_rules", EmitDefaultValue = false)]
        public List<QueryLabelRule> LabelRules { get; set; }

        /// <summary>
        /// 扩展区状态，\&quot;ON\&quot;代表上线，\&quot;OFF\&quot;代表下线，只有上线的扩展区才能被用户看到
        /// </summary>
        /// <value>扩展区状态，\&quot;ON\&quot;代表上线，\&quot;OFF\&quot;代表下线，只有上线的扩展区才能被用户看到</value>
        [DataMember(Name = "status", EmitDefaultValue = false)]
        public string Status { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class QueryExtension {\n");
            sb.Append("  Areas: ").Append(Areas).Append("\n");
            sb.Append("  ExtensionKey: ").Append(ExtensionKey).Append("\n");
            sb.Append("  LabelRules: ").Append(LabelRules).Append("\n");
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
            return this.Equals(input as QueryExtension);
        }

        /// <summary>
        /// Returns true if QueryExtension instances are equal
        /// </summary>
        /// <param name="input">Instance of QueryExtension to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(QueryExtension input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Areas == input.Areas ||
                    this.Areas != null &&
                    input.Areas != null &&
                    this.Areas.SequenceEqual(input.Areas)
                ) && 
                (
                    this.ExtensionKey == input.ExtensionKey ||
                    (this.ExtensionKey != null &&
                    this.ExtensionKey.Equals(input.ExtensionKey))
                ) && 
                (
                    this.LabelRules == input.LabelRules ||
                    this.LabelRules != null &&
                    input.LabelRules != null &&
                    this.LabelRules.SequenceEqual(input.LabelRules)
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
                if (this.Areas != null)
                {
                    hashCode = (hashCode * 59) + this.Areas.GetHashCode();
                }
                if (this.ExtensionKey != null)
                {
                    hashCode = (hashCode * 59) + this.ExtensionKey.GetHashCode();
                }
                if (this.LabelRules != null)
                {
                    hashCode = (hashCode * 59) + this.LabelRules.GetHashCode();
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
