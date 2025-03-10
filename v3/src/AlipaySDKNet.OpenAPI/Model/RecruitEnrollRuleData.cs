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
    /// RecruitEnrollRuleData
    /// </summary>
    [DataContract(Name = "RecruitEnrollRuleData")]
    public partial class RecruitEnrollRuleData : IEquatable<RecruitEnrollRuleData>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RecruitEnrollRuleData" /> class.
        /// </summary>
        /// <param name="recruitVoucherRules">招商方案可提报的券的规则列表，不同的券有不同的规则。.</param>
        /// <param name="schema">素材的要求，json字符串，使用时需要把此字符串解析成json对象。 field：提报的字段key label：字段说明 required：是否必填 type：字段类型。包含：图片（IMAGE）、文本（TEXT）、数据源（DATASOURCE）等 rules：字段约束规则   图片（IMAGE）：     image_size：图片宽高，单位是PX     file_type：图片类型     file_size：表示图片大小的最大值，单位是KB     image_aspect_ratio: 图片宽高比例   文本（TEXT）：     unicode_length：文本长度，单位为Byte   数据源（DATASOURCE）：     unicode_length：文本长度，单位为Byte.</param>
        public RecruitEnrollRuleData(List<RecruitVoucherRule> recruitVoucherRules = default(List<RecruitVoucherRule>), string schema = default(string))
        {
            this.RecruitVoucherRules = recruitVoucherRules;
            this.Schema = schema;
        }

        /// <summary>
        /// 招商方案可提报的券的规则列表，不同的券有不同的规则。
        /// </summary>
        /// <value>招商方案可提报的券的规则列表，不同的券有不同的规则。</value>
        [DataMember(Name = "recruit_voucher_rules", EmitDefaultValue = false)]
        public List<RecruitVoucherRule> RecruitVoucherRules { get; set; }

        /// <summary>
        /// 素材的要求，json字符串，使用时需要把此字符串解析成json对象。 field：提报的字段key label：字段说明 required：是否必填 type：字段类型。包含：图片（IMAGE）、文本（TEXT）、数据源（DATASOURCE）等 rules：字段约束规则   图片（IMAGE）：     image_size：图片宽高，单位是PX     file_type：图片类型     file_size：表示图片大小的最大值，单位是KB     image_aspect_ratio: 图片宽高比例   文本（TEXT）：     unicode_length：文本长度，单位为Byte   数据源（DATASOURCE）：     unicode_length：文本长度，单位为Byte
        /// </summary>
        /// <value>素材的要求，json字符串，使用时需要把此字符串解析成json对象。 field：提报的字段key label：字段说明 required：是否必填 type：字段类型。包含：图片（IMAGE）、文本（TEXT）、数据源（DATASOURCE）等 rules：字段约束规则   图片（IMAGE）：     image_size：图片宽高，单位是PX     file_type：图片类型     file_size：表示图片大小的最大值，单位是KB     image_aspect_ratio: 图片宽高比例   文本（TEXT）：     unicode_length：文本长度，单位为Byte   数据源（DATASOURCE）：     unicode_length：文本长度，单位为Byte</value>
        [DataMember(Name = "schema", EmitDefaultValue = false)]
        public string Schema { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class RecruitEnrollRuleData {\n");
            sb.Append("  RecruitVoucherRules: ").Append(RecruitVoucherRules).Append("\n");
            sb.Append("  Schema: ").Append(Schema).Append("\n");
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
            return this.Equals(input as RecruitEnrollRuleData);
        }

        /// <summary>
        /// Returns true if RecruitEnrollRuleData instances are equal
        /// </summary>
        /// <param name="input">Instance of RecruitEnrollRuleData to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(RecruitEnrollRuleData input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.RecruitVoucherRules == input.RecruitVoucherRules ||
                    this.RecruitVoucherRules != null &&
                    input.RecruitVoucherRules != null &&
                    this.RecruitVoucherRules.SequenceEqual(input.RecruitVoucherRules)
                ) && 
                (
                    this.Schema == input.Schema ||
                    (this.Schema != null &&
                    this.Schema.Equals(input.Schema))
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
                if (this.RecruitVoucherRules != null)
                {
                    hashCode = (hashCode * 59) + this.RecruitVoucherRules.GetHashCode();
                }
                if (this.Schema != null)
                {
                    hashCode = (hashCode * 59) + this.Schema.GetHashCode();
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
