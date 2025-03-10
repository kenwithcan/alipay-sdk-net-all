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
    /// CloudResumePositionIntention
    /// </summary>
    [DataContract(Name = "CloudResumePositionIntention")]
    public partial class CloudResumePositionIntention : IEquatable<CloudResumePositionIntention>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CloudResumePositionIntention" /> class.
        /// </summary>
        /// <param name="intentionCity">意向城市Code。具体地区编码参见https://lbs.amap.com/api/webservice/download 里面城市编码表.</param>
        /// <param name="jobId">职业id(这个字段在目前版本不对外暴露).</param>
        /// <param name="jobName">职业名称.</param>
        /// <param name="professionId">行业id(这个字段在目前版本不对外暴露).</param>
        /// <param name="professionName">行业名称.</param>
        /// <param name="salaryMax">最大工资.</param>
        /// <param name="salaryMin">最小薪资.</param>
        /// <param name="salaryUnit">工资单位，/月 /日.</param>
        /// <param name="workProperty">工作属性.</param>
        public CloudResumePositionIntention(string intentionCity = default(string), string jobId = default(string), string jobName = default(string), string professionId = default(string), string professionName = default(string), string salaryMax = default(string), string salaryMin = default(string), string salaryUnit = default(string), string workProperty = default(string))
        {
            this.IntentionCity = intentionCity;
            this.JobId = jobId;
            this.JobName = jobName;
            this.ProfessionId = professionId;
            this.ProfessionName = professionName;
            this.SalaryMax = salaryMax;
            this.SalaryMin = salaryMin;
            this.SalaryUnit = salaryUnit;
            this.WorkProperty = workProperty;
        }

        /// <summary>
        /// 意向城市Code。具体地区编码参见https://lbs.amap.com/api/webservice/download 里面城市编码表
        /// </summary>
        /// <value>意向城市Code。具体地区编码参见https://lbs.amap.com/api/webservice/download 里面城市编码表</value>
        [DataMember(Name = "intention_city", EmitDefaultValue = false)]
        public string IntentionCity { get; set; }

        /// <summary>
        /// 职业id(这个字段在目前版本不对外暴露)
        /// </summary>
        /// <value>职业id(这个字段在目前版本不对外暴露)</value>
        [DataMember(Name = "job_id", EmitDefaultValue = false)]
        [Obsolete]
        public string JobId { get; set; }

        /// <summary>
        /// 职业名称
        /// </summary>
        /// <value>职业名称</value>
        [DataMember(Name = "job_name", EmitDefaultValue = false)]
        public string JobName { get; set; }

        /// <summary>
        /// 行业id(这个字段在目前版本不对外暴露)
        /// </summary>
        /// <value>行业id(这个字段在目前版本不对外暴露)</value>
        [DataMember(Name = "profession_id", EmitDefaultValue = false)]
        [Obsolete]
        public string ProfessionId { get; set; }

        /// <summary>
        /// 行业名称
        /// </summary>
        /// <value>行业名称</value>
        [DataMember(Name = "profession_name", EmitDefaultValue = false)]
        public string ProfessionName { get; set; }

        /// <summary>
        /// 最大工资
        /// </summary>
        /// <value>最大工资</value>
        [DataMember(Name = "salary_max", EmitDefaultValue = false)]
        public string SalaryMax { get; set; }

        /// <summary>
        /// 最小薪资
        /// </summary>
        /// <value>最小薪资</value>
        [DataMember(Name = "salary_min", EmitDefaultValue = false)]
        public string SalaryMin { get; set; }

        /// <summary>
        /// 工资单位，/月 /日
        /// </summary>
        /// <value>工资单位，/月 /日</value>
        [DataMember(Name = "salary_unit", EmitDefaultValue = false)]
        public string SalaryUnit { get; set; }

        /// <summary>
        /// 工作属性
        /// </summary>
        /// <value>工作属性</value>
        [DataMember(Name = "work_property", EmitDefaultValue = false)]
        public string WorkProperty { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class CloudResumePositionIntention {\n");
            sb.Append("  IntentionCity: ").Append(IntentionCity).Append("\n");
            sb.Append("  JobId: ").Append(JobId).Append("\n");
            sb.Append("  JobName: ").Append(JobName).Append("\n");
            sb.Append("  ProfessionId: ").Append(ProfessionId).Append("\n");
            sb.Append("  ProfessionName: ").Append(ProfessionName).Append("\n");
            sb.Append("  SalaryMax: ").Append(SalaryMax).Append("\n");
            sb.Append("  SalaryMin: ").Append(SalaryMin).Append("\n");
            sb.Append("  SalaryUnit: ").Append(SalaryUnit).Append("\n");
            sb.Append("  WorkProperty: ").Append(WorkProperty).Append("\n");
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
            return this.Equals(input as CloudResumePositionIntention);
        }

        /// <summary>
        /// Returns true if CloudResumePositionIntention instances are equal
        /// </summary>
        /// <param name="input">Instance of CloudResumePositionIntention to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CloudResumePositionIntention input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.IntentionCity == input.IntentionCity ||
                    (this.IntentionCity != null &&
                    this.IntentionCity.Equals(input.IntentionCity))
                ) && 
                (
                    this.JobId == input.JobId ||
                    (this.JobId != null &&
                    this.JobId.Equals(input.JobId))
                ) && 
                (
                    this.JobName == input.JobName ||
                    (this.JobName != null &&
                    this.JobName.Equals(input.JobName))
                ) && 
                (
                    this.ProfessionId == input.ProfessionId ||
                    (this.ProfessionId != null &&
                    this.ProfessionId.Equals(input.ProfessionId))
                ) && 
                (
                    this.ProfessionName == input.ProfessionName ||
                    (this.ProfessionName != null &&
                    this.ProfessionName.Equals(input.ProfessionName))
                ) && 
                (
                    this.SalaryMax == input.SalaryMax ||
                    (this.SalaryMax != null &&
                    this.SalaryMax.Equals(input.SalaryMax))
                ) && 
                (
                    this.SalaryMin == input.SalaryMin ||
                    (this.SalaryMin != null &&
                    this.SalaryMin.Equals(input.SalaryMin))
                ) && 
                (
                    this.SalaryUnit == input.SalaryUnit ||
                    (this.SalaryUnit != null &&
                    this.SalaryUnit.Equals(input.SalaryUnit))
                ) && 
                (
                    this.WorkProperty == input.WorkProperty ||
                    (this.WorkProperty != null &&
                    this.WorkProperty.Equals(input.WorkProperty))
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
                if (this.IntentionCity != null)
                {
                    hashCode = (hashCode * 59) + this.IntentionCity.GetHashCode();
                }
                if (this.JobId != null)
                {
                    hashCode = (hashCode * 59) + this.JobId.GetHashCode();
                }
                if (this.JobName != null)
                {
                    hashCode = (hashCode * 59) + this.JobName.GetHashCode();
                }
                if (this.ProfessionId != null)
                {
                    hashCode = (hashCode * 59) + this.ProfessionId.GetHashCode();
                }
                if (this.ProfessionName != null)
                {
                    hashCode = (hashCode * 59) + this.ProfessionName.GetHashCode();
                }
                if (this.SalaryMax != null)
                {
                    hashCode = (hashCode * 59) + this.SalaryMax.GetHashCode();
                }
                if (this.SalaryMin != null)
                {
                    hashCode = (hashCode * 59) + this.SalaryMin.GetHashCode();
                }
                if (this.SalaryUnit != null)
                {
                    hashCode = (hashCode * 59) + this.SalaryUnit.GetHashCode();
                }
                if (this.WorkProperty != null)
                {
                    hashCode = (hashCode * 59) + this.WorkProperty.GetHashCode();
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
