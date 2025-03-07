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
    /// AlipayOpenPublicMatchuserLabelDeleteModel
    /// </summary>
    [DataContract(Name = "AlipayOpenPublicMatchuserLabelDeleteModel")]
    public partial class AlipayOpenPublicMatchuserLabelDeleteModel : IEquatable<AlipayOpenPublicMatchuserLabelDeleteModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenPublicMatchuserLabelDeleteModel" /> class.
        /// </summary>
        /// <param name="labelId">标签 id，只支持生活号自定义标签。通过 &lt;a href&#x3D;\&quot;https://opendocs.alipay.com/apis/api_6/alipay.open.public.life.label.create\&quot;&gt;alipay.open.public.life.label.create&lt;/a&gt;(创建标签接口)创建自定义标签后获取。.</param>
        /// <param name="matchers">支付宝用户匹配器列表，最多传入10条.</param>
        public AlipayOpenPublicMatchuserLabelDeleteModel(string labelId = default(string), List<Matcher> matchers = default(List<Matcher>))
        {
            this.LabelId = labelId;
            this.Matchers = matchers;
        }

        /// <summary>
        /// 标签 id，只支持生活号自定义标签。通过 &lt;a href&#x3D;\&quot;https://opendocs.alipay.com/apis/api_6/alipay.open.public.life.label.create\&quot;&gt;alipay.open.public.life.label.create&lt;/a&gt;(创建标签接口)创建自定义标签后获取。
        /// </summary>
        /// <value>标签 id，只支持生活号自定义标签。通过 &lt;a href&#x3D;\&quot;https://opendocs.alipay.com/apis/api_6/alipay.open.public.life.label.create\&quot;&gt;alipay.open.public.life.label.create&lt;/a&gt;(创建标签接口)创建自定义标签后获取。</value>
        [DataMember(Name = "label_id", EmitDefaultValue = false)]
        public string LabelId { get; set; }

        /// <summary>
        /// 支付宝用户匹配器列表，最多传入10条
        /// </summary>
        /// <value>支付宝用户匹配器列表，最多传入10条</value>
        [DataMember(Name = "matchers", EmitDefaultValue = false)]
        public List<Matcher> Matchers { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenPublicMatchuserLabelDeleteModel {\n");
            sb.Append("  LabelId: ").Append(LabelId).Append("\n");
            sb.Append("  Matchers: ").Append(Matchers).Append("\n");
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
            return this.Equals(input as AlipayOpenPublicMatchuserLabelDeleteModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenPublicMatchuserLabelDeleteModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenPublicMatchuserLabelDeleteModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenPublicMatchuserLabelDeleteModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.LabelId == input.LabelId ||
                    (this.LabelId != null &&
                    this.LabelId.Equals(input.LabelId))
                ) && 
                (
                    this.Matchers == input.Matchers ||
                    this.Matchers != null &&
                    input.Matchers != null &&
                    this.Matchers.SequenceEqual(input.Matchers)
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
                if (this.LabelId != null)
                {
                    hashCode = (hashCode * 59) + this.LabelId.GetHashCode();
                }
                if (this.Matchers != null)
                {
                    hashCode = (hashCode * 59) + this.Matchers.GetHashCode();
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
