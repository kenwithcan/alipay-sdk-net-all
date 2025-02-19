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
    /// AlipayCommerceEducateCampusInstitutionsAddModel
    /// </summary>
    [DataContract(Name = "AlipayCommerceEducateCampusInstitutionsAddModel")]
    public partial class AlipayCommerceEducateCampusInstitutionsAddModel : IEquatable<AlipayCommerceEducateCampusInstitutionsAddModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayCommerceEducateCampusInstitutionsAddModel" /> class.
        /// </summary>
        /// <param name="cardPictUrl">事业单位法人证书或办学许可证的图片。入驻学校时，如果流入人工审核，会根据此图片进行辅助验证。.</param>
        /// <param name="cityCode">市.</param>
        /// <param name="instName">入驻的学校名称，必须是完整的学校全称.</param>
        /// <param name="instStdCode">学校外标，使用统一社会信用编码.</param>
        /// <param name="learningStage">办学阶段。 枚举值如下： KINDERGARTEN（幼儿园） PRIMARY_SCHOOL（小学）  MIDDLE_SCHOOL（初中）  HIGH_SCHOOL（高中） SECONDARY_VOCATIONAL_SCHOOL（中职中专）  注意：如果学校兼有多种属性，可以连写用英文逗号拆分，如：MIDDLE_SCHOOL,HIGH_SCHOOL 代表兼有初中部和高中部；.</param>
        /// <param name="provinceCode">省份.</param>
        /// <param name="schoolProperty">学校性质.枚举值如下：  1：公立  2：民办.</param>
        public AlipayCommerceEducateCampusInstitutionsAddModel(string cardPictUrl = default(string), string cityCode = default(string), string instName = default(string), string instStdCode = default(string), string learningStage = default(string), string provinceCode = default(string), string schoolProperty = default(string))
        {
            this.CardPictUrl = cardPictUrl;
            this.CityCode = cityCode;
            this.InstName = instName;
            this.InstStdCode = instStdCode;
            this.LearningStage = learningStage;
            this.ProvinceCode = provinceCode;
            this.SchoolProperty = schoolProperty;
        }

        /// <summary>
        /// 事业单位法人证书或办学许可证的图片。入驻学校时，如果流入人工审核，会根据此图片进行辅助验证。
        /// </summary>
        /// <value>事业单位法人证书或办学许可证的图片。入驻学校时，如果流入人工审核，会根据此图片进行辅助验证。</value>
        [DataMember(Name = "card_pict_url", EmitDefaultValue = false)]
        public string CardPictUrl { get; set; }

        /// <summary>
        /// 市
        /// </summary>
        /// <value>市</value>
        [DataMember(Name = "city_code", EmitDefaultValue = false)]
        public string CityCode { get; set; }

        /// <summary>
        /// 入驻的学校名称，必须是完整的学校全称
        /// </summary>
        /// <value>入驻的学校名称，必须是完整的学校全称</value>
        [DataMember(Name = "inst_name", EmitDefaultValue = false)]
        public string InstName { get; set; }

        /// <summary>
        /// 学校外标，使用统一社会信用编码
        /// </summary>
        /// <value>学校外标，使用统一社会信用编码</value>
        [DataMember(Name = "inst_std_code", EmitDefaultValue = false)]
        public string InstStdCode { get; set; }

        /// <summary>
        /// 办学阶段。 枚举值如下： KINDERGARTEN（幼儿园） PRIMARY_SCHOOL（小学）  MIDDLE_SCHOOL（初中）  HIGH_SCHOOL（高中） SECONDARY_VOCATIONAL_SCHOOL（中职中专）  注意：如果学校兼有多种属性，可以连写用英文逗号拆分，如：MIDDLE_SCHOOL,HIGH_SCHOOL 代表兼有初中部和高中部；
        /// </summary>
        /// <value>办学阶段。 枚举值如下： KINDERGARTEN（幼儿园） PRIMARY_SCHOOL（小学）  MIDDLE_SCHOOL（初中）  HIGH_SCHOOL（高中） SECONDARY_VOCATIONAL_SCHOOL（中职中专）  注意：如果学校兼有多种属性，可以连写用英文逗号拆分，如：MIDDLE_SCHOOL,HIGH_SCHOOL 代表兼有初中部和高中部；</value>
        [DataMember(Name = "learning_stage", EmitDefaultValue = false)]
        public string LearningStage { get; set; }

        /// <summary>
        /// 省份
        /// </summary>
        /// <value>省份</value>
        [DataMember(Name = "province_code", EmitDefaultValue = false)]
        public string ProvinceCode { get; set; }

        /// <summary>
        /// 学校性质.枚举值如下：  1：公立  2：民办
        /// </summary>
        /// <value>学校性质.枚举值如下：  1：公立  2：民办</value>
        [DataMember(Name = "school_property", EmitDefaultValue = false)]
        public string SchoolProperty { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayCommerceEducateCampusInstitutionsAddModel {\n");
            sb.Append("  CardPictUrl: ").Append(CardPictUrl).Append("\n");
            sb.Append("  CityCode: ").Append(CityCode).Append("\n");
            sb.Append("  InstName: ").Append(InstName).Append("\n");
            sb.Append("  InstStdCode: ").Append(InstStdCode).Append("\n");
            sb.Append("  LearningStage: ").Append(LearningStage).Append("\n");
            sb.Append("  ProvinceCode: ").Append(ProvinceCode).Append("\n");
            sb.Append("  SchoolProperty: ").Append(SchoolProperty).Append("\n");
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
            return this.Equals(input as AlipayCommerceEducateCampusInstitutionsAddModel);
        }

        /// <summary>
        /// Returns true if AlipayCommerceEducateCampusInstitutionsAddModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayCommerceEducateCampusInstitutionsAddModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayCommerceEducateCampusInstitutionsAddModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.CardPictUrl == input.CardPictUrl ||
                    (this.CardPictUrl != null &&
                    this.CardPictUrl.Equals(input.CardPictUrl))
                ) && 
                (
                    this.CityCode == input.CityCode ||
                    (this.CityCode != null &&
                    this.CityCode.Equals(input.CityCode))
                ) && 
                (
                    this.InstName == input.InstName ||
                    (this.InstName != null &&
                    this.InstName.Equals(input.InstName))
                ) && 
                (
                    this.InstStdCode == input.InstStdCode ||
                    (this.InstStdCode != null &&
                    this.InstStdCode.Equals(input.InstStdCode))
                ) && 
                (
                    this.LearningStage == input.LearningStage ||
                    (this.LearningStage != null &&
                    this.LearningStage.Equals(input.LearningStage))
                ) && 
                (
                    this.ProvinceCode == input.ProvinceCode ||
                    (this.ProvinceCode != null &&
                    this.ProvinceCode.Equals(input.ProvinceCode))
                ) && 
                (
                    this.SchoolProperty == input.SchoolProperty ||
                    (this.SchoolProperty != null &&
                    this.SchoolProperty.Equals(input.SchoolProperty))
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
                if (this.CardPictUrl != null)
                {
                    hashCode = (hashCode * 59) + this.CardPictUrl.GetHashCode();
                }
                if (this.CityCode != null)
                {
                    hashCode = (hashCode * 59) + this.CityCode.GetHashCode();
                }
                if (this.InstName != null)
                {
                    hashCode = (hashCode * 59) + this.InstName.GetHashCode();
                }
                if (this.InstStdCode != null)
                {
                    hashCode = (hashCode * 59) + this.InstStdCode.GetHashCode();
                }
                if (this.LearningStage != null)
                {
                    hashCode = (hashCode * 59) + this.LearningStage.GetHashCode();
                }
                if (this.ProvinceCode != null)
                {
                    hashCode = (hashCode * 59) + this.ProvinceCode.GetHashCode();
                }
                if (this.SchoolProperty != null)
                {
                    hashCode = (hashCode * 59) + this.SchoolProperty.GetHashCode();
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
