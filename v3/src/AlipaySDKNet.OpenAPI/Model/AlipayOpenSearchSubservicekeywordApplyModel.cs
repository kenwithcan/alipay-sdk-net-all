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
    /// AlipayOpenSearchSubservicekeywordApplyModel
    /// </summary>
    [DataContract(Name = "AlipayOpenSearchSubservicekeywordApplyModel")]
    public partial class AlipayOpenSearchSubservicekeywordApplyModel : IEquatable<AlipayOpenSearchSubservicekeywordApplyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenSearchSubservicekeywordApplyModel" /> class.
        /// </summary>
        /// <param name="configId">关键词配置id，由支付宝生成，关键词申请通过后会通知接口返回，也可以申请单状态获取.</param>
        /// <param name="keyWords">服务关键词列表，每批最多传入30个，关键词长度小于12个汉字。 超过数量限制会申请失败，剩余关键词可通过 &lt;a href&#x3D;\&quot;https://opendocs.alipay.com/mini/062ndt?pathHash&#x3D;e3e78b68&amp;ref&#x3D;api&amp;scene&#x3D;common\&quot;&gt;alipay.open.search.appkeywordquota.query&lt;/a&gt;查询.</param>
        /// <param name="subServiceCode">子服务code，提报服务关键词，alipay.open.app.service.list.query(服务批量查询)这个接口可以获取.</param>
        /// <param name="targetAppid">小程序id.</param>
        public AlipayOpenSearchSubservicekeywordApplyModel(string configId = default(string), List<string> keyWords = default(List<string>), string subServiceCode = default(string), string targetAppid = default(string))
        {
            this.ConfigId = configId;
            this.KeyWords = keyWords;
            this.SubServiceCode = subServiceCode;
            this.TargetAppid = targetAppid;
        }

        /// <summary>
        /// 关键词配置id，由支付宝生成，关键词申请通过后会通知接口返回，也可以申请单状态获取
        /// </summary>
        /// <value>关键词配置id，由支付宝生成，关键词申请通过后会通知接口返回，也可以申请单状态获取</value>
        [DataMember(Name = "config_id", EmitDefaultValue = false)]
        public string ConfigId { get; set; }

        /// <summary>
        /// 服务关键词列表，每批最多传入30个，关键词长度小于12个汉字。 超过数量限制会申请失败，剩余关键词可通过 &lt;a href&#x3D;\&quot;https://opendocs.alipay.com/mini/062ndt?pathHash&#x3D;e3e78b68&amp;ref&#x3D;api&amp;scene&#x3D;common\&quot;&gt;alipay.open.search.appkeywordquota.query&lt;/a&gt;查询
        /// </summary>
        /// <value>服务关键词列表，每批最多传入30个，关键词长度小于12个汉字。 超过数量限制会申请失败，剩余关键词可通过 &lt;a href&#x3D;\&quot;https://opendocs.alipay.com/mini/062ndt?pathHash&#x3D;e3e78b68&amp;ref&#x3D;api&amp;scene&#x3D;common\&quot;&gt;alipay.open.search.appkeywordquota.query&lt;/a&gt;查询</value>
        [DataMember(Name = "key_words", EmitDefaultValue = false)]
        public List<string> KeyWords { get; set; }

        /// <summary>
        /// 子服务code，提报服务关键词，alipay.open.app.service.list.query(服务批量查询)这个接口可以获取
        /// </summary>
        /// <value>子服务code，提报服务关键词，alipay.open.app.service.list.query(服务批量查询)这个接口可以获取</value>
        [DataMember(Name = "sub_service_code", EmitDefaultValue = false)]
        public string SubServiceCode { get; set; }

        /// <summary>
        /// 小程序id
        /// </summary>
        /// <value>小程序id</value>
        [DataMember(Name = "target_appid", EmitDefaultValue = false)]
        public string TargetAppid { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenSearchSubservicekeywordApplyModel {\n");
            sb.Append("  ConfigId: ").Append(ConfigId).Append("\n");
            sb.Append("  KeyWords: ").Append(KeyWords).Append("\n");
            sb.Append("  SubServiceCode: ").Append(SubServiceCode).Append("\n");
            sb.Append("  TargetAppid: ").Append(TargetAppid).Append("\n");
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
            return this.Equals(input as AlipayOpenSearchSubservicekeywordApplyModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenSearchSubservicekeywordApplyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenSearchSubservicekeywordApplyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenSearchSubservicekeywordApplyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ConfigId == input.ConfigId ||
                    (this.ConfigId != null &&
                    this.ConfigId.Equals(input.ConfigId))
                ) && 
                (
                    this.KeyWords == input.KeyWords ||
                    this.KeyWords != null &&
                    input.KeyWords != null &&
                    this.KeyWords.SequenceEqual(input.KeyWords)
                ) && 
                (
                    this.SubServiceCode == input.SubServiceCode ||
                    (this.SubServiceCode != null &&
                    this.SubServiceCode.Equals(input.SubServiceCode))
                ) && 
                (
                    this.TargetAppid == input.TargetAppid ||
                    (this.TargetAppid != null &&
                    this.TargetAppid.Equals(input.TargetAppid))
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
                if (this.ConfigId != null)
                {
                    hashCode = (hashCode * 59) + this.ConfigId.GetHashCode();
                }
                if (this.KeyWords != null)
                {
                    hashCode = (hashCode * 59) + this.KeyWords.GetHashCode();
                }
                if (this.SubServiceCode != null)
                {
                    hashCode = (hashCode * 59) + this.SubServiceCode.GetHashCode();
                }
                if (this.TargetAppid != null)
                {
                    hashCode = (hashCode * 59) + this.TargetAppid.GetHashCode();
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
