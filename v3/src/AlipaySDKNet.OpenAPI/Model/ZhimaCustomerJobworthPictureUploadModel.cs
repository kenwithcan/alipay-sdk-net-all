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
    /// ZhimaCustomerJobworthPictureUploadModel
    /// </summary>
    [DataContract(Name = "ZhimaCustomerJobworthPictureUploadModel")]
    public partial class ZhimaCustomerJobworthPictureUploadModel : IEquatable<ZhimaCustomerJobworthPictureUploadModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCustomerJobworthPictureUploadModel" /> class.
        /// </summary>
        /// <param name="content">图片对应的base64字符串，支持jpg和png，1M之内.</param>
        /// <param name="picType">只能传入指定类型，具体类型看文档.</param>
        public ZhimaCustomerJobworthPictureUploadModel(string content = default(string), string picType = default(string))
        {
            this.Content = content;
            this.PicType = picType;
        }

        /// <summary>
        /// 图片对应的base64字符串，支持jpg和png，1M之内
        /// </summary>
        /// <value>图片对应的base64字符串，支持jpg和png，1M之内</value>
        [DataMember(Name = "content", EmitDefaultValue = false)]
        public string Content { get; set; }

        /// <summary>
        /// 只能传入指定类型，具体类型看文档
        /// </summary>
        /// <value>只能传入指定类型，具体类型看文档</value>
        [DataMember(Name = "pic_type", EmitDefaultValue = false)]
        public string PicType { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ZhimaCustomerJobworthPictureUploadModel {\n");
            sb.Append("  Content: ").Append(Content).Append("\n");
            sb.Append("  PicType: ").Append(PicType).Append("\n");
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
            return this.Equals(input as ZhimaCustomerJobworthPictureUploadModel);
        }

        /// <summary>
        /// Returns true if ZhimaCustomerJobworthPictureUploadModel instances are equal
        /// </summary>
        /// <param name="input">Instance of ZhimaCustomerJobworthPictureUploadModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ZhimaCustomerJobworthPictureUploadModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Content == input.Content ||
                    (this.Content != null &&
                    this.Content.Equals(input.Content))
                ) && 
                (
                    this.PicType == input.PicType ||
                    (this.PicType != null &&
                    this.PicType.Equals(input.PicType))
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
                if (this.Content != null)
                {
                    hashCode = (hashCode * 59) + this.Content.GetHashCode();
                }
                if (this.PicType != null)
                {
                    hashCode = (hashCode * 59) + this.PicType.GetHashCode();
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
