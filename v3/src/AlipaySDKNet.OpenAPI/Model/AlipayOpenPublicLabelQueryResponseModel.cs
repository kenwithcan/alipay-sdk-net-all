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
    /// AlipayOpenPublicLabelQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicLabelQueryResponseModel")]
    public partial class AlipayOpenPublicLabelQueryResponseModel : IEquatable<AlipayOpenPublicLabelQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicLabelQueryResponseModel" /> class.
        /// </summary>
        /// <param name="labelList">该服务窗拥有的标签列表.</param>
        public AlipayOpenPublicLabelQueryResponseModel(List<PublicLabel> labelList = default(List<PublicLabel>))
        {
            this.LabelList = labelList;
        }

        /// <summary>
        /// 该服务窗拥有的标签列表
        /// </summary>
        /// <value>该服务窗拥有的标签列表</value>
        [DataMember(Name = "label_list", EmitDefaultValue = false)]
        public List<PublicLabel> LabelList { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicLabelQueryResponseModel {\n");
            sb.Append("  LabelList: ").Append(LabelList).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicLabelQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicLabelQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicLabelQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicLabelQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.LabelList == input.LabelList ||
                    this.LabelList != null &&
                    input.LabelList != null &&
                    this.LabelList.SequenceEqual(input.LabelList)
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
                if (this.LabelList != null)
                {
                    hashCode = (hashCode * 59) + this.LabelList.GetHashCode();
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
