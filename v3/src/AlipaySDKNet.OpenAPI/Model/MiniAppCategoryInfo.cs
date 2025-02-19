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
    /// MiniAppCategoryInfo
    /// </summary>
    [DataContract(Name = "MiniAppCategoryInfo")]
    public partial class MiniAppCategoryInfo : IEquatable<MiniAppCategoryInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="MiniAppCategoryInfo" /> class.
        /// </summary>
        /// <param name="firstCategoryId">一级类目id.</param>
        /// <param name="firstCategoryName">一级类目名称.</param>
        /// <param name="secondCategoryId">二级类目id.</param>
        /// <param name="secondCategoryName">二级类目名称.</param>
        /// <param name="thirdCategoryId">三级类目id，可空.</param>
        /// <param name="thirdCategoryName">三级类目名称，可空.</param>
        public MiniAppCategoryInfo(string firstCategoryId = default(string), string firstCategoryName = default(string), string secondCategoryId = default(string), string secondCategoryName = default(string), string thirdCategoryId = default(string), string thirdCategoryName = default(string))
        {
            this.FirstCategoryId = firstCategoryId;
            this.FirstCategoryName = firstCategoryName;
            this.SecondCategoryId = secondCategoryId;
            this.SecondCategoryName = secondCategoryName;
            this.ThirdCategoryId = thirdCategoryId;
            this.ThirdCategoryName = thirdCategoryName;
        }

        /// <summary>
        /// 一级类目id
        /// </summary>
        /// <value>一级类目id</value>
        [DataMember(Name = "first_category_id", EmitDefaultValue = false)]
        public string FirstCategoryId { get; set; }

        /// <summary>
        /// 一级类目名称
        /// </summary>
        /// <value>一级类目名称</value>
        [DataMember(Name = "first_category_name", EmitDefaultValue = false)]
        public string FirstCategoryName { get; set; }

        /// <summary>
        /// 二级类目id
        /// </summary>
        /// <value>二级类目id</value>
        [DataMember(Name = "second_category_id", EmitDefaultValue = false)]
        public string SecondCategoryId { get; set; }

        /// <summary>
        /// 二级类目名称
        /// </summary>
        /// <value>二级类目名称</value>
        [DataMember(Name = "second_category_name", EmitDefaultValue = false)]
        public string SecondCategoryName { get; set; }

        /// <summary>
        /// 三级类目id，可空
        /// </summary>
        /// <value>三级类目id，可空</value>
        [DataMember(Name = "third_category_id", EmitDefaultValue = false)]
        public string ThirdCategoryId { get; set; }

        /// <summary>
        /// 三级类目名称，可空
        /// </summary>
        /// <value>三级类目名称，可空</value>
        [DataMember(Name = "third_category_name", EmitDefaultValue = false)]
        public string ThirdCategoryName { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class MiniAppCategoryInfo {\n");
            sb.Append("  FirstCategoryId: ").Append(FirstCategoryId).Append("\n");
            sb.Append("  FirstCategoryName: ").Append(FirstCategoryName).Append("\n");
            sb.Append("  SecondCategoryId: ").Append(SecondCategoryId).Append("\n");
            sb.Append("  SecondCategoryName: ").Append(SecondCategoryName).Append("\n");
            sb.Append("  ThirdCategoryId: ").Append(ThirdCategoryId).Append("\n");
            sb.Append("  ThirdCategoryName: ").Append(ThirdCategoryName).Append("\n");
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
            return this.Equals(input as MiniAppCategoryInfo);
        }

        /// <summary>
        /// Returns true if MiniAppCategoryInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of MiniAppCategoryInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(MiniAppCategoryInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.FirstCategoryId == input.FirstCategoryId ||
                    (this.FirstCategoryId != null &&
                    this.FirstCategoryId.Equals(input.FirstCategoryId))
                ) && 
                (
                    this.FirstCategoryName == input.FirstCategoryName ||
                    (this.FirstCategoryName != null &&
                    this.FirstCategoryName.Equals(input.FirstCategoryName))
                ) && 
                (
                    this.SecondCategoryId == input.SecondCategoryId ||
                    (this.SecondCategoryId != null &&
                    this.SecondCategoryId.Equals(input.SecondCategoryId))
                ) && 
                (
                    this.SecondCategoryName == input.SecondCategoryName ||
                    (this.SecondCategoryName != null &&
                    this.SecondCategoryName.Equals(input.SecondCategoryName))
                ) && 
                (
                    this.ThirdCategoryId == input.ThirdCategoryId ||
                    (this.ThirdCategoryId != null &&
                    this.ThirdCategoryId.Equals(input.ThirdCategoryId))
                ) && 
                (
                    this.ThirdCategoryName == input.ThirdCategoryName ||
                    (this.ThirdCategoryName != null &&
                    this.ThirdCategoryName.Equals(input.ThirdCategoryName))
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
                if (this.FirstCategoryId != null)
                {
                    hashCode = (hashCode * 59) + this.FirstCategoryId.GetHashCode();
                }
                if (this.FirstCategoryName != null)
                {
                    hashCode = (hashCode * 59) + this.FirstCategoryName.GetHashCode();
                }
                if (this.SecondCategoryId != null)
                {
                    hashCode = (hashCode * 59) + this.SecondCategoryId.GetHashCode();
                }
                if (this.SecondCategoryName != null)
                {
                    hashCode = (hashCode * 59) + this.SecondCategoryName.GetHashCode();
                }
                if (this.ThirdCategoryId != null)
                {
                    hashCode = (hashCode * 59) + this.ThirdCategoryId.GetHashCode();
                }
                if (this.ThirdCategoryName != null)
                {
                    hashCode = (hashCode * 59) + this.ThirdCategoryName.GetHashCode();
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
