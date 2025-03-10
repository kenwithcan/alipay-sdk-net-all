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
    /// AlipayOpenPublicDefaultExtensionCreateResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicDefaultExtensionCreateResponseModel")]
    public partial class AlipayOpenPublicDefaultExtensionCreateResponseModel : IEquatable<AlipayOpenPublicDefaultExtensionCreateResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicDefaultExtensionCreateResponseModel" /> class.
        /// </summary>
        /// <param name="extensionKey">一套扩展区的key，创建一套扩展区成功后，支付宝会将该字段返回，后续对扩展区进行删除等操作都会用到这个值。.</param>
        public AlipayOpenPublicDefaultExtensionCreateResponseModel(string extensionKey = default(string))
        {
            this.ExtensionKey = extensionKey;
        }

        /// <summary>
        /// 一套扩展区的key，创建一套扩展区成功后，支付宝会将该字段返回，后续对扩展区进行删除等操作都会用到这个值。
        /// </summary>
        /// <value>一套扩展区的key，创建一套扩展区成功后，支付宝会将该字段返回，后续对扩展区进行删除等操作都会用到这个值。</value>
        [DataMember(Name = "extension_key", EmitDefaultValue = false)]
        public string ExtensionKey { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicDefaultExtensionCreateResponseModel {\n");
            sb.Append("  ExtensionKey: ").Append(ExtensionKey).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicDefaultExtensionCreateResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicDefaultExtensionCreateResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicDefaultExtensionCreateResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicDefaultExtensionCreateResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ExtensionKey == input.ExtensionKey ||
                    (this.ExtensionKey != null &&
                    this.ExtensionKey.Equals(input.ExtensionKey))
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
                if (this.ExtensionKey != null)
                {
                    hashCode = (hashCode * 59) + this.ExtensionKey.GetHashCode();
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
