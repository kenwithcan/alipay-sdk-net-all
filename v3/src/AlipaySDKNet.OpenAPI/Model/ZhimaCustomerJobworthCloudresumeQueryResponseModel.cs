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
    /// ZhimaCustomerJobworthCloudresumeQueryResponseModel
    /// </summary>
    [DataContract(Name = "ZhimaCustomerJobworthCloudresumeQueryResponseModel")]
    public partial class ZhimaCustomerJobworthCloudresumeQueryResponseModel : IEquatable<ZhimaCustomerJobworthCloudresumeQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ZhimaCustomerJobworthCloudresumeQueryResponseModel" /> class.
        /// </summary>
        /// <param name="birthday">出生日期.</param>
        /// <param name="certificates">证书名称.</param>
        /// <param name="educationExperiences">教育经历.</param>
        /// <param name="email">用户在芝麻工作证填写的邮箱.</param>
        /// <param name="gender">性别.</param>
        /// <param name="intentionStatus">用户的求职状态.</param>
        /// <param name="personDesc">用户在芝麻工作证填写的自我介绍.</param>
        /// <param name="phone">手机号码.</param>
        /// <param name="picUrl">picUrl.</param>
        /// <param name="positionIntentions">求职期望.</param>
        /// <param name="positionType">职业身份.</param>
        /// <param name="residentialArea">常驻地址.</param>
        /// <param name="skills">技能信息.</param>
        /// <param name="userName">姓名.</param>
        /// <param name="workExperiences">工作经历.</param>
        /// <param name="workStartDate">工作开始日期（时间戳）.</param>
        public ZhimaCustomerJobworthCloudresumeQueryResponseModel(string birthday = default(string), List<CloudResumeCertificateInfo> certificates = default(List<CloudResumeCertificateInfo>), List<CloudResumeEducationExperience> educationExperiences = default(List<CloudResumeEducationExperience>), string email = default(string), string gender = default(string), string intentionStatus = default(string), string personDesc = default(string), string phone = default(string), CloudResumeHeadPic picUrl = default(CloudResumeHeadPic), List<CloudResumePositionIntention> positionIntentions = default(List<CloudResumePositionIntention>), string positionType = default(string), string residentialArea = default(string), List<CloudResumeSkillInfo> skills = default(List<CloudResumeSkillInfo>), string userName = default(string), List<CloudResumeWorkExperience> workExperiences = default(List<CloudResumeWorkExperience>), int workStartDate = default(int))
        {
            this.Birthday = birthday;
            this.Certificates = certificates;
            this.EducationExperiences = educationExperiences;
            this.Email = email;
            this.Gender = gender;
            this.IntentionStatus = intentionStatus;
            this.PersonDesc = personDesc;
            this.Phone = phone;
            this.PicUrl = picUrl;
            this.PositionIntentions = positionIntentions;
            this.PositionType = positionType;
            this.ResidentialArea = residentialArea;
            this.Skills = skills;
            this.UserName = userName;
            this.WorkExperiences = workExperiences;
            this.WorkStartDate = workStartDate;
        }

        /// <summary>
        /// 出生日期
        /// </summary>
        /// <value>出生日期</value>
        [DataMember(Name = "birthday", EmitDefaultValue = false)]
        public string Birthday { get; set; }

        /// <summary>
        /// 证书名称
        /// </summary>
        /// <value>证书名称</value>
        [DataMember(Name = "certificates", EmitDefaultValue = false)]
        public List<CloudResumeCertificateInfo> Certificates { get; set; }

        /// <summary>
        /// 教育经历
        /// </summary>
        /// <value>教育经历</value>
        [DataMember(Name = "education_experiences", EmitDefaultValue = false)]
        public List<CloudResumeEducationExperience> EducationExperiences { get; set; }

        /// <summary>
        /// 用户在芝麻工作证填写的邮箱
        /// </summary>
        /// <value>用户在芝麻工作证填写的邮箱</value>
        [DataMember(Name = "email", EmitDefaultValue = false)]
        public string Email { get; set; }

        /// <summary>
        /// 性别
        /// </summary>
        /// <value>性别</value>
        [DataMember(Name = "gender", EmitDefaultValue = false)]
        public string Gender { get; set; }

        /// <summary>
        /// 用户的求职状态
        /// </summary>
        /// <value>用户的求职状态</value>
        [DataMember(Name = "intention_status", EmitDefaultValue = false)]
        public string IntentionStatus { get; set; }

        /// <summary>
        /// 用户在芝麻工作证填写的自我介绍
        /// </summary>
        /// <value>用户在芝麻工作证填写的自我介绍</value>
        [DataMember(Name = "person_desc", EmitDefaultValue = false)]
        public string PersonDesc { get; set; }

        /// <summary>
        /// 手机号码
        /// </summary>
        /// <value>手机号码</value>
        [DataMember(Name = "phone", EmitDefaultValue = false)]
        public string Phone { get; set; }

        /// <summary>
        /// Gets or Sets PicUrl
        /// </summary>
        [DataMember(Name = "pic_url", EmitDefaultValue = false)]
        public CloudResumeHeadPic PicUrl { get; set; }

        /// <summary>
        /// 求职期望
        /// </summary>
        /// <value>求职期望</value>
        [DataMember(Name = "position_intentions", EmitDefaultValue = false)]
        public List<CloudResumePositionIntention> PositionIntentions { get; set; }

        /// <summary>
        /// 职业身份
        /// </summary>
        /// <value>职业身份</value>
        [DataMember(Name = "position_type", EmitDefaultValue = false)]
        public string PositionType { get; set; }

        /// <summary>
        /// 常驻地址
        /// </summary>
        /// <value>常驻地址</value>
        [DataMember(Name = "residential_area", EmitDefaultValue = false)]
        public string ResidentialArea { get; set; }

        /// <summary>
        /// 技能信息
        /// </summary>
        /// <value>技能信息</value>
        [DataMember(Name = "skills", EmitDefaultValue = false)]
        public List<CloudResumeSkillInfo> Skills { get; set; }

        /// <summary>
        /// 姓名
        /// </summary>
        /// <value>姓名</value>
        [DataMember(Name = "user_name", EmitDefaultValue = false)]
        public string UserName { get; set; }

        /// <summary>
        /// 工作经历
        /// </summary>
        /// <value>工作经历</value>
        [DataMember(Name = "work_experiences", EmitDefaultValue = false)]
        public List<CloudResumeWorkExperience> WorkExperiences { get; set; }

        /// <summary>
        /// 工作开始日期（时间戳）
        /// </summary>
        /// <value>工作开始日期（时间戳）</value>
        [DataMember(Name = "work_start_date", EmitDefaultValue = false)]
        public int WorkStartDate { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ZhimaCustomerJobworthCloudresumeQueryResponseModel {\n");
            sb.Append("  Birthday: ").Append(Birthday).Append("\n");
            sb.Append("  Certificates: ").Append(Certificates).Append("\n");
            sb.Append("  EducationExperiences: ").Append(EducationExperiences).Append("\n");
            sb.Append("  Email: ").Append(Email).Append("\n");
            sb.Append("  Gender: ").Append(Gender).Append("\n");
            sb.Append("  IntentionStatus: ").Append(IntentionStatus).Append("\n");
            sb.Append("  PersonDesc: ").Append(PersonDesc).Append("\n");
            sb.Append("  Phone: ").Append(Phone).Append("\n");
            sb.Append("  PicUrl: ").Append(PicUrl).Append("\n");
            sb.Append("  PositionIntentions: ").Append(PositionIntentions).Append("\n");
            sb.Append("  PositionType: ").Append(PositionType).Append("\n");
            sb.Append("  ResidentialArea: ").Append(ResidentialArea).Append("\n");
            sb.Append("  Skills: ").Append(Skills).Append("\n");
            sb.Append("  UserName: ").Append(UserName).Append("\n");
            sb.Append("  WorkExperiences: ").Append(WorkExperiences).Append("\n");
            sb.Append("  WorkStartDate: ").Append(WorkStartDate).Append("\n");
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
            return this.Equals(input as ZhimaCustomerJobworthCloudresumeQueryResponseModel);
        }

        /// <summary>
        /// Returns true if ZhimaCustomerJobworthCloudresumeQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of ZhimaCustomerJobworthCloudresumeQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ZhimaCustomerJobworthCloudresumeQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Birthday == input.Birthday ||
                    (this.Birthday != null &&
                    this.Birthday.Equals(input.Birthday))
                ) && 
                (
                    this.Certificates == input.Certificates ||
                    this.Certificates != null &&
                    input.Certificates != null &&
                    this.Certificates.SequenceEqual(input.Certificates)
                ) && 
                (
                    this.EducationExperiences == input.EducationExperiences ||
                    this.EducationExperiences != null &&
                    input.EducationExperiences != null &&
                    this.EducationExperiences.SequenceEqual(input.EducationExperiences)
                ) && 
                (
                    this.Email == input.Email ||
                    (this.Email != null &&
                    this.Email.Equals(input.Email))
                ) && 
                (
                    this.Gender == input.Gender ||
                    (this.Gender != null &&
                    this.Gender.Equals(input.Gender))
                ) && 
                (
                    this.IntentionStatus == input.IntentionStatus ||
                    (this.IntentionStatus != null &&
                    this.IntentionStatus.Equals(input.IntentionStatus))
                ) && 
                (
                    this.PersonDesc == input.PersonDesc ||
                    (this.PersonDesc != null &&
                    this.PersonDesc.Equals(input.PersonDesc))
                ) && 
                (
                    this.Phone == input.Phone ||
                    (this.Phone != null &&
                    this.Phone.Equals(input.Phone))
                ) && 
                (
                    this.PicUrl == input.PicUrl ||
                    (this.PicUrl != null &&
                    this.PicUrl.Equals(input.PicUrl))
                ) && 
                (
                    this.PositionIntentions == input.PositionIntentions ||
                    this.PositionIntentions != null &&
                    input.PositionIntentions != null &&
                    this.PositionIntentions.SequenceEqual(input.PositionIntentions)
                ) && 
                (
                    this.PositionType == input.PositionType ||
                    (this.PositionType != null &&
                    this.PositionType.Equals(input.PositionType))
                ) && 
                (
                    this.ResidentialArea == input.ResidentialArea ||
                    (this.ResidentialArea != null &&
                    this.ResidentialArea.Equals(input.ResidentialArea))
                ) && 
                (
                    this.Skills == input.Skills ||
                    this.Skills != null &&
                    input.Skills != null &&
                    this.Skills.SequenceEqual(input.Skills)
                ) && 
                (
                    this.UserName == input.UserName ||
                    (this.UserName != null &&
                    this.UserName.Equals(input.UserName))
                ) && 
                (
                    this.WorkExperiences == input.WorkExperiences ||
                    this.WorkExperiences != null &&
                    input.WorkExperiences != null &&
                    this.WorkExperiences.SequenceEqual(input.WorkExperiences)
                ) && 
                (
                    this.WorkStartDate == input.WorkStartDate ||
                    this.WorkStartDate.Equals(input.WorkStartDate)
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
                if (this.Birthday != null)
                {
                    hashCode = (hashCode * 59) + this.Birthday.GetHashCode();
                }
                if (this.Certificates != null)
                {
                    hashCode = (hashCode * 59) + this.Certificates.GetHashCode();
                }
                if (this.EducationExperiences != null)
                {
                    hashCode = (hashCode * 59) + this.EducationExperiences.GetHashCode();
                }
                if (this.Email != null)
                {
                    hashCode = (hashCode * 59) + this.Email.GetHashCode();
                }
                if (this.Gender != null)
                {
                    hashCode = (hashCode * 59) + this.Gender.GetHashCode();
                }
                if (this.IntentionStatus != null)
                {
                    hashCode = (hashCode * 59) + this.IntentionStatus.GetHashCode();
                }
                if (this.PersonDesc != null)
                {
                    hashCode = (hashCode * 59) + this.PersonDesc.GetHashCode();
                }
                if (this.Phone != null)
                {
                    hashCode = (hashCode * 59) + this.Phone.GetHashCode();
                }
                if (this.PicUrl != null)
                {
                    hashCode = (hashCode * 59) + this.PicUrl.GetHashCode();
                }
                if (this.PositionIntentions != null)
                {
                    hashCode = (hashCode * 59) + this.PositionIntentions.GetHashCode();
                }
                if (this.PositionType != null)
                {
                    hashCode = (hashCode * 59) + this.PositionType.GetHashCode();
                }
                if (this.ResidentialArea != null)
                {
                    hashCode = (hashCode * 59) + this.ResidentialArea.GetHashCode();
                }
                if (this.Skills != null)
                {
                    hashCode = (hashCode * 59) + this.Skills.GetHashCode();
                }
                if (this.UserName != null)
                {
                    hashCode = (hashCode * 59) + this.UserName.GetHashCode();
                }
                if (this.WorkExperiences != null)
                {
                    hashCode = (hashCode * 59) + this.WorkExperiences.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.WorkStartDate.GetHashCode();
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
