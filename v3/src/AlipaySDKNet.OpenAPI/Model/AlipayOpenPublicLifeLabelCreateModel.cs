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
    /// AlipayOpenPublicLifeLabelCreateModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicLifeLabelCreateModel")]
    public partial class AlipayOpenPublicLifeLabelCreateModel : IEquatable<AlipayOpenPublicLifeLabelCreateModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicLifeLabelCreateModel" /> class.
        /// </summary>
        /// <param name="dataType">标签值类型，不填默认为 string 类型。 注意：目前只支持 string（字符串类型）。.</param>
        /// <param name="labelName">自定义标签名。 注意：每个生活号最多创建 100 个自定义标签。.</param>
        public AlipayOpenPublicLifeLabelCreateModel(string dataType = default(string), string labelName = default(string))
        {
            this.DataType = dataType;
            this.LabelName = labelName;
        }

        /// <summary>
        /// 标签值类型，不填默认为 string 类型。 注意：目前只支持 string（字符串类型）。
        /// </summary>
        /// <value>标签值类型，不填默认为 string 类型。 注意：目前只支持 string（字符串类型）。</value>
        [DataMember(Name = "data_type", EmitDefaultValue = false)]
        public string DataType { get; set; }

        /// <summary>
        /// 自定义标签名。 注意：每个生活号最多创建 100 个自定义标签。
        /// </summary>
        /// <value>自定义标签名。 注意：每个生活号最多创建 100 个自定义标签。</value>
        [DataMember(Name = "label_name", EmitDefaultValue = false)]
        public string LabelName { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicLifeLabelCreateModel {\n");
            sb.Append("  DataType: ").Append(DataType).Append("\n");
            sb.Append("  LabelName: ").Append(LabelName).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicLifeLabelCreateModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicLifeLabelCreateModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicLifeLabelCreateModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicLifeLabelCreateModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.DataType == input.DataType ||
                    (this.DataType != null &&
                    this.DataType.Equals(input.DataType))
                ) && 
                (
                    this.LabelName == input.LabelName ||
                    (this.LabelName != null &&
                    this.LabelName.Equals(input.LabelName))
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
                if (this.DataType != null)
                {
                    hashCode = (hashCode * 59) + this.DataType.GetHashCode();
                }
                if (this.LabelName != null)
                {
                    hashCode = (hashCode * 59) + this.LabelName.GetHashCode();
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
