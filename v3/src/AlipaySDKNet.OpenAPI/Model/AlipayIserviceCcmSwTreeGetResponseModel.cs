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
    /// AlipayIserviceCcmSwTreeGetResponseModel
    /// </summary>
    [DataContract(Name = "AlipayIserviceCcmSwTreeGetResponseModel")]
    public partial class AlipayIserviceCcmSwTreeGetResponseModel : IEquatable<AlipayIserviceCcmSwTreeGetResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayIserviceCcmSwTreeGetResponseModel" /> class.
        /// </summary>
        /// <param name="tree">类目树字符串.</param>
        public AlipayIserviceCcmSwTreeGetResponseModel(string tree = default(string))
        {
            this.Tree = tree;
        }

        /// <summary>
        /// 类目树字符串
        /// </summary>
        /// <value>类目树字符串</value>
        [DataMember(Name = "tree", EmitDefaultValue = false)]
        public string Tree { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayIserviceCcmSwTreeGetResponseModel {\n");
            sb.Append("  Tree: ").Append(Tree).Append("\n");
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
            return this.Equals(input as AlipayIserviceCcmSwTreeGetResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayIserviceCcmSwTreeGetResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayIserviceCcmSwTreeGetResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayIserviceCcmSwTreeGetResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Tree == input.Tree ||
                    (this.Tree != null &&
                    this.Tree.Equals(input.Tree))
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
                if (this.Tree != null)
                {
                    hashCode = (hashCode * 59) + this.Tree.GetHashCode();
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
